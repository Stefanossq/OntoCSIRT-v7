#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
soar_webhook.py - servico HTTP que liga o OntoCSIRT v7 a um SOAR (Shuffle, Cortex XSOAR, TheHive...).

POST /alert   corpo JSON, por exemplo:
    {"src_ip": "1.2.3.4", "attack_type": "SQLi", "target": "Server_1"}
  campos opcionais: "alert_id", "cve" (ex. "CVE-2023-34362"), "cwe" (ex. "CWE-89"),
                    "cvss" (0-10), "attribute" ("confidentiality"|"integrity"|"availability")
resposta 200:
    {"action": "Deploy WAF rule", "action_iri": "CoA_WAFRule", "confidence": 0.62,
     "requires_human_approval": true, "risk_level": "High", "neighbors": [...], ...}
POST /retain  {"alert_id": "...", "solution": "CoA_Isolate", "analyst": "nome", "rationale": "porque ..."}
  o analista aprova (revise) a acao de um alerta ja tratado por /alert; o incidente e um :Case com
  solutionProvenance "analyst:retain" sao gravados em --acquired depois de SHACL + HermiT + Pellet
  (ontoevo.cases.CaseAcquirer.retain) e passam a ser recuperaveis nos alertas seguintes.
GET /health   estado e base carregada

Pipeline por alerta (o mesmo do cenario do artigo, ontocsirt_v7.add_scenario):
  1. normaliza o alerta (attack_type -> AttackPattern + CWE; target -> Asset; src_ip -> ator externo);
  1b. "cve" ausente da base (SPARQL ASK): nvd_enricher.NVDEnricher consulta o NVD (cache 24 h, limite de
      pedidos), valida o ramo Vulnerability + CWE (SHACL + HermiT), grava-o em --acquired e recarrega a base;
      se o NVD falhar -> 200 {"action": "manual_review", "fallback": true, "reason": ...} (README_NVD.md);
  2. cria o Incident e liga-o com owl:differentFrom aos incidentes da base;
  3. SHACL do alerta (avisos, nao bloqueia: um alerta real vem quase sempre incompleto);
  4. Pellet (Owlready2) com as regras SWRL: risco (R1), fraqueza partilhada (R5), solucao candidata (R6);
  5. recuperacao CBR com a similaridade ponderada do v7 (ontocsirt_v7.sim) e voto ponderado no top-k.

"confidence" NAO e uma probabilidade calibrada. E definida como
    confidence = similaridade do caso mais proximo x fracao (ponderada pela similaridade)
                 dos top-k casos que votam na acao vencedora
ou seja, "quao parecido e o caso mais proximo" x "quanto os vizinhos concordam". Abaixo de
--min-confidence a resposta pede aprovacao humana (requires_human_approval = true).

Uso:
  python soar_webhook.py                                   # base OntoCSIRT_v7.ttl, porta 8088, so localhost
  python soar_webhook.py --kb OntoCSIRT_v7_real.ttl        # base gerada pelo ingest_real_cases.py
  python soar_webhook.py --token SEGREDO --host 0.0.0.0    # exige cabecalho X-OntoCSIRT-Token
  python soar_webhook.py --once '{"src_ip":"1.2.3.4","attack_type":"SQLi","target":"Server_1"}'   # sem servidor
"""
import argparse
import hmac
import ipaddress
import json
import os
import re
import sys
import threading
import time
from collections import OrderedDict, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from rdflib import Graph, Literal
from rdflib.namespace import OWL, RDF, RDFS, XSD

import ontocsirt_v7 as v7
import validar_ingestao as val

OC = v7.OC
MAX_BODY = 16 * 1024

# attack_type do SIEM/IDS -> (padrao de ataque do v7, CWE tipico). Aceita sinonimos comuns.
ATTACK_TYPES = {
    "sqli": ("AP_SQLInjection", "CWE_89"), "sql injection": ("AP_SQLInjection", "CWE_89"),
    "xss": ("AP_XSS", "CWE_79"), "cross-site scripting": ("AP_XSS", "CWE_79"),
    "csrf": ("AP_CSRF", "CWE_352"),
    "cmdi": ("AP_CommandInjection", "CWE_78"), "command injection": ("AP_CommandInjection", "CWE_78"),
    "rce": ("AP_CommandInjection", "CWE_78"),
    "idor": ("AP_IDOR", "CWE_639"), "authz bypass": ("AP_AuthzBypass", "CWE_862"),
    "brute force": ("AP_CredentialAbuse", "CWE_287"), "bruteforce": ("AP_CredentialAbuse", "CWE_287"),
    "credential stuffing": ("AP_CredentialAbuse", "CWE_287"), "hardcoded credentials": ("AP_CredentialAbuse", "CWE_798"),
    "path traversal": ("AP_PathTraversal", "CWE_22"), "lfi": ("AP_PathTraversal", "CWE_22"),
    "file upload": ("AP_MaliciousUpload", "CWE_434"), "webshell": ("AP_MaliciousUpload", "CWE_434"),
    "deserialization": ("AP_Deserialization", "CWE_502"), "ssrf": ("AP_SSRF", "CWE_918"),
}
ATTRS = {"confidentiality": "State_Confidentiality", "integrity": "State_Integrity", "availability": "State_Availability"}
# Atributo por omissao quando o alerta nao o traz (decisao declarada, devolvida em "assumptions")
DEFAULT_ATTR = {"AP_XSS": "State_Integrity", "AP_CSRF": "State_Integrity", "AP_CommandInjection": "State_Integrity",
                "AP_Deserialization": "State_Integrity", "AP_MaliciousUpload": "State_Integrity"}
# Acao da ontologia -> nome e playbook para o SOAR
SOAR_ACTIONS = {
    "CoA_WAFRule": ("Deploy WAF rule", "waf_block_pattern"),
    "CoA_Isolate": ("Isolate asset", "edr_isolate_host"),
    "CoA_Patch": ("Apply patch", "open_patch_ticket"),
    "CoA_Segment": ("Segment network", "fw_segment_asset"),
    "CoA_AccessControlFix": ("Fix authorization control", "open_appsec_ticket"),
    "CoA_RotateCredentials": ("Rotate credentials", "iam_rotate_credentials"),
    "CoA_ApplyMitigation": ("Apply vendor mitigation", "open_mitigation_ticket"),
    "CoA_Decommission": ("Decommission product", "open_decommission_ticket"),
}

# As features vem da hierarquia do grafo (ontocsirt_v7.features): o ator VERIS Unknown (casos do KEV),
# novos tipos de ativo e subcategorias criadas pela evolucao entram sem listas fixas aqui.
features = v7.features


class BadAlert(ValueError):
    pass


def slug(s):
    return re.sub(r"[^A-Za-z0-9]+", "_", str(s)).strip("_")[:60]


class Engine:
    """Mantem a base em memoria; cada alerta raciocina numa copia (base + triplas do alerta)."""

    def __init__(self, kb, k=3, min_conf=0.5, reasoner="pellet", acquired=None, enricher=None):
        self.kb_path, self.k, self.min_conf, self.reasoner = kb, k, min_conf, reasoner
        self.acquired = acquired
        # nvd_enricher.NVDEnricher: CVE do alerta ausente da base -> NVD em tempo real -> ramo gravado em acquired
        self.enricher = enricher if acquired else None
        self.enrich_lock = threading.Lock()              # um enriquecimento de cada vez (ficheiro de dados + recarga)
        self.lock = threading.Lock()                     # Owlready2/Pellet: um raciocinio de cada vez
        self.recent = OrderedDict()                      # alert_id -> (incidente, triplas): para /retain
        self._load()

    def _load(self):
        base = Graph()
        base.parse(self.kb_path, format="turtle")
        if (val.EXT_ONTOLOGY, OWL.versionInfo, Literal(val.EXT_VERSION)) not in base:
            base.parse(val.EXT, format="turtle")        # sourceAddress, alertId, UnknownActor, proveniencia
        if os.path.exists(val.EVO) and (val.EVO_ONTOLOGY, RDF.type, OWL.Ontology) not in base:
            base.parse(val.EVO, format="turtle")        # classes e relacoes aprovadas pela evolucao
        if self.acquired and os.path.exists(self.acquired):
            base.parse(self.acquired, format="turtle")  # vulnerabilidades e casos adquiridos (ontoevo)
            import ingest_real_cases as ing
            ing.remove_all_different(base)
            ing.add_all_different(base)
        self.base = base
        self.n_incidents = len(set(self.base.subjects(RDF.type, OC.Incident)))

    def profile(self):
        """Perfil de composicao da base (ontoevo.kb) para gravar casos retidos; None = base avulsa."""
        p = os.path.abspath(self.kb_path)
        if p == os.path.abspath(os.path.join(v7.HERE, "OntoCSIRT_v7_real.ttl")):
            return "real"
        if p == os.path.abspath(v7.TTL):
            return "base"
        return None

    def retain(self, body):
        """POST /retain: o analista aprova a acao de um alerta tratado -> caso "analyst:retain" na base."""
        if not isinstance(body, dict):
            raise BadAlert("corpo deve ser um objeto JSON")
        aid = slug(body.get("alert_id", ""))
        if aid not in self.recent:
            return 404, {"error": "alerta %r nao foi tratado por este servico (ou expirou)" % body.get("alert_id")}
        if self.profile() is None or not self.acquired:
            return 501, {"error": "retencao so com --kb OntoCSIRT_v7_real.ttl ou OntoCSIRT_v7.ttl e --acquired"}
        from ontoevo.cases import CaseAcquirer
        incident, triples = self.recent[aid]
        with self.lock:
            code, res = CaseAcquirer(profile=self.profile(), acquired_path=self.acquired,
                                     use_pellet=self.reasoner == "pellet").retain(
                incident, triples, str(body.get("solution", "")), str(body.get("analyst", "")),
                str(body.get("rationale", "")), aid)
            if code == 200:
                self.recent.pop(aid, None)
                self._load()                             # o caso retido passa a ser recuperavel
        return code, res

    # --------------------------------------------------------------- 1. normalizacao
    def normalize(self, alert):
        if not isinstance(alert, dict):
            raise BadAlert("corpo deve ser um objeto JSON")
        assumptions = []
        try:
            ip = str(ipaddress.ip_address(str(alert.get("src_ip", "")).strip()))
        except ValueError:
            raise BadAlert("src_ip ausente ou invalido")
        at = str(alert.get("attack_type", "")).strip().lower().replace("_", " ")
        if at not in ATTACK_TYPES:
            raise BadAlert("attack_type desconhecido: %r (aceites: %s)" % (alert.get("attack_type"), ", ".join(sorted(ATTACK_TYPES))))
        ap, cwe = ATTACK_TYPES[at]
        if alert.get("cwe"):
            m = re.match(r"^CWE-(\d+)$", str(alert["cwe"]).strip().upper())
            if not m:
                raise BadAlert("cwe mal formado (esperado CWE-<n>)")
            cwe = "CWE_" + m.group(1)
            if (OC[cwe], OC.cweId, None) not in self.base:
                raise BadAlert("%s nao existe na base" % alert["cwe"])
        else:
            assumptions.append("CWE inferido do attack_type: %s" % cwe.replace("_", "-"))
        target = slug(alert.get("target", ""))
        if not target:
            raise BadAlert("target ausente")
        asset = target if target.startswith("Asset_") else "Asset_" + target
        if (OC[asset], RDF.type, None) not in self.base:
            # ativo desconhecido: tipo pelo prefixo do nome (Server_, Database_, Gateway_, Workstation_)
            kind = next((c for c in ("Server", "Database", "Gateway", "Workstation") if target.lower().startswith(c.lower())), "Server")
            assumptions.append("ativo %s nao existe na base: criado como %s" % (asset, kind))
            new_asset = kind
        else:
            new_asset = None
        attr = ATTRS.get(str(alert.get("attribute", "")).lower())
        if attr is None:
            attr = DEFAULT_ATTR.get(ap, "State_Confidentiality")
            assumptions.append("atributo CIA nao informado: assumido %s" % attr.split("_")[1])
        cvss = alert.get("cvss")
        if cvss is not None:
            try:
                cvss = float(cvss)
            except (TypeError, ValueError):
                raise BadAlert("cvss deve ser numerico")
        cve = alert.get("cve")
        if cve is not None and not re.match(r"^CVE-\d{4}-\d{4,}$", str(cve)):
            raise BadAlert("cve mal formado")
        aid = slug(alert.get("alert_id") or "%d" % int(time.time() * 1000))
        return dict(ip=ip, ap=ap, cwe=cwe, cwe_explicit=bool(alert.get("cwe")), asset=asset, new_asset=new_asset,
                    attr=attr, cvss=cvss, cve=cve, alert_id=aid, assumptions=assumptions)

    # --------------------------------------------------------------- 1b. CVE desconhecida -> NVD
    def cve_in_kb(self, cve):
        """A CVE ja e uma Vulnerability da base? (SPARQL ASK sobre a base carregada)"""
        return bool(self.base.query(v7.PFX + 'ASK { ?v a :Vulnerability ; :cveId ?id . FILTER(STR(?id) = "%s") }'
                                    % cve).askAnswer)

    def enrich_cve(self, n):
        """Consulta o NVD, grava o ramo (Vulnerability + CWE) no ficheiro de dados e recarrega a base.
        Devolve (relatorio, None) se a CVE ficou na base, ou (None, resposta_fallback) se nao foi possivel."""
        import nvd_enricher as ne
        cve = n["cve"]
        try:
            with self.enrich_lock:
                if self.cve_in_kb(cve):                  # outro pedido acabou de a adquirir
                    return {"cve": cve, "status": "present"}, None
                rep = self.enricher.enrich_detailed(
                    cve, self.acquired, fallback_cwe=n["cwe"].replace("_", "-") if n["cwe_explicit"] else None)
                with self.lock:                          # nao recarrega a meio de um raciocinio
                    self._load()
            n["assumptions"].append("%s adquirida do NVD em tempo real (%s): CVSS %s, %s"
                                    % (cve, rep["nvd"]["source"], rep["cvss"], rep["cwe"]))
            return rep, None
        except ne.NVDError as e:
            reason = {"nvd_unavailable": "CVE nao encontrado na base e API NVD indisponivel",
                      "cve_not_found": "CVE nao encontrado na base nem no NVD",
                      "enrichment_rejected": "CVE nao encontrado na base e o registo do NVD nao permite criar o ramo"}[e.kind]
            return None, {"alert_id": n["alert_id"], "action": "manual_review", "action_iri": None,
                          "playbook": "manual_triage", "confidence": 0.0, "requires_human_approval": True,
                          "reason": reason, "fallback": True,
                          "nvd": {"cve": cve, "error": e.kind, "detail": str(e)},
                          "assumptions": n["assumptions"],
                          "mode": "decision-support: sem a vulnerabilidade na base nao ha recomendacao automatica"}

    # --------------------------------------------------------------- 2. triplas do incidente
    def triples(self, n):
        I, A, V = OC["Incident_Alert_" + n["alert_id"]], OC["Act_Alert_" + n["alert_id"]], None
        actor = OC["Actor_SRC_" + slug(n["ip"])]
        t = [(actor, RDF.type, OC.ExternalActor),                 # IP de origem externo: VERIS actor.External
             (actor, RDFS.label, Literal("Origem %s (alerta)" % n["ip"])),
             (actor, OC.sourceAddress, Literal(n["ip"])),
             (A, RDF.type, OC.ThreatAction), (A, OC.instantiatesPattern, OC[n["ap"]]),
             (I, RDF.type, OC.Incident), (I, RDFS.label, Literal("Alerta %s" % n["alert_id"])),
             (I, OC.alertId, Literal(n["alert_id"])), (I, OC.hasActor, actor), (I, OC.hasAction, A),
             (I, OC.hasAsset, OC[n["asset"]]), (I, OC.hasAttribute, OC[n["attr"]])]
        if n["new_asset"]:
            t += [(OC[n["asset"]], RDF.type, OC[n["new_asset"]]), (OC[n["asset"]], RDFS.label, Literal(n["asset"]))]
        # Reutiliza a vulnerabilidade da base se o alerta trouxer uma CVE conhecida
        if n["cve"]:
            V = next(iter(self.base.subjects(OC.cveId, Literal(n["cve"]))), None)
        if V is not None:
            # a CWE usada e a da vulnerabilidade da base, nao a deduzida do attack_type: corrige o pressuposto
            used = self.base.value(V, OC.hasWeakness)
            n["assumptions"] = [a for a in n["assumptions"] if not a.startswith("CWE inferido do attack_type")]
            n["assumptions"].append("CWE da vulnerabilidade %s na base: %s" % (n["cve"], str(self.base.value(used, OC.cweId) or v7.short(used))))
        if V is None:
            V = OC["Vuln_Alert_" + n["alert_id"]]
            t += [(V, RDF.type, OC.Vulnerability), (V, OC.hasWeakness, OC[n["cwe"]])]
            if n["cve"]:
                t.append((V, OC.cveId, Literal(n["cve"])))
            if n["cvss"] is not None:
                t.append((V, OC.cvssBaseScore, Literal(str(n["cvss"]), datatype=XSD.decimal)))
        t += [(I, OC.involvesVulnerability, V), (A, OC.exploits, V)]
        return I, t

    # --------------------------------------------------------------- 3-5. processamento
    def handle(self, alert):
        t0 = time.time()
        n = self.normalize(alert)
        enrichment = None
        if n["cve"] and self.enricher is not None and not self.cve_in_kb(n["cve"]):
            enrichment, fallback = self.enrich_cve(n)
            if fallback is not None:
                fallback["elapsed_seconds"] = round(time.time() - t0, 2)
                return 200, fallback                     # o SOAR ramifica em requires_human_approval
        I, new = self.triples(n)                         # com a CVE na base, o alerta reutiliza a Vulnerability
        self.recent[n["alert_id"]] = (I, list(new))
        while len(self.recent) > 200:
            self.recent.popitem(last=False)
        g = Graph()
        for x in self.base:
            g.add(x)
        for x in new:
            g.add(x)
        for j in self.base.subjects(RDF.type, OC.Incident):        # sem nomes unicos: R3-R6 precisam disto
            g.add((I, OWL.differentFrom, j))
        warnings = self.shacl_warnings(g, I, n)

        if self.reasoner == "pellet":
            with self.lock:
                ok, dt, ig, _, _ = v7.run_pellet(g)
            if not ok:
                return 422, {"error": "o alerta torna a base inconsistente (Pellet)", "alert_id": n["alert_id"]}
        else:
            ig, dt = g, 0.0
        qi = v7.short(I)
        risk = v7.q(ig, "SELECT ?r WHERE { :%s :hasRiskLevel ?r }" % qi)
        r6 = sorted({r[0] for r in v7.q(ig, "SELECT ?s WHERE { :%s :candidateSolution ?s }" % qi)})
        shares = sorted({r[0] for r in v7.q(ig, "SELECT ?j WHERE { :%s :sharesWeaknessWith ?j }" % qi)})

        F = features(ig)
        if qi not in F:
            return 500, {"error": "incidente do alerta sem atributos de recuperacao", "alert_id": n["alert_id"]}
        qf = F.pop(qi)
        ranked = sorted(((v7.sim(qf, f), i, f["sol"]) for i, f in F.items() if f["sol"]), key=lambda x: (-x[0], x[1]))
        top = ranked[:self.k]
        votes = defaultdict(float)
        for s, _, sol in top:
            votes[sol] += s
        total = sum(votes.values())
        if not top or total == 0:
            action, share, conf = None, 0.0, 0.0
        else:
            action = max(sorted(votes), key=lambda a: votes[a])
            share = votes[action] / total
            conf = round(top[0][0] * share, 3)
        # acao sem playbook mapeado (p.ex. criada pela evolucao): nome = rdfs:label da ontologia
        label = self.base.value(OC[action], RDFS.label) if action else None
        name, playbook = SOAR_ACTIONS.get(action, (str(label) if label is not None else action, None))
        return 200, {
            "alert_id": n["alert_id"], "incident": qi,
            "action": name, "action_iri": action, "playbook": playbook,
            "confidence": conf, "requires_human_approval": conf < self.min_conf,
            "confidence_definition": "sim(top1) x fracao ponderada dos top-%d que votam na acao; nao calibrada" % self.k,
            "support": {"top1_similarity": top[0][0] if top else 0.0, "vote_share": round(share, 3),
                        "agreeing_cases": [i for s, i, sol in top if sol == action]},
            "neighbors": [{"case_incident": i, "similarity": s, "solution": sol} for s, i, sol in top],
            "risk_level": risk[0][0] if risk else None,
            "rule_inferences": {"R5_sharesWeaknessWith": shares[:20], "R5_count": len(shares), "R6_candidateSolution": r6},
            "assumptions": n["assumptions"], "warnings": warnings,
            "nvd_enrichment": enrichment,
            "reasoner": {"name": "Pellet (Owlready2 %s)" % v7.o2.VERSION if self.reasoner == "pellet" else "nenhum (so SPARQL)",
                         "consistent": True, "seconds": round(dt, 2)},
            "kb": {"file": os.path.basename(self.kb_path), "incidents": self.n_incidents},
            "elapsed_seconds": round(time.time() - t0, 2),
            "mode": "decision-support: a acao e uma recomendacao; a execucao automatica e decisao do SOAR",
        }

    def shacl_warnings(self, g, I, n):
        """SHACL so sobre os nos do alerta. Nao bloqueia: devolve o que falta para inferir mais."""
        # valida so o subgrafo do alerta (+ tipos dos nos que ele referencia): ~10x mais rapido que a base toda
        sub = Graph()
        for s, p, o in g:
            if s in (I, OC["Vuln_Alert_" + n["alert_id"]], OC["Act_Alert_" + n["alert_id"]], OC["Actor_SRC_" + slug(n["ip"])]) \
                    and p != OWL.differentFrom:
                sub.add((s, p, o))
                if p == RDF.type:
                    continue                      # o e uma classe: a TBox vem de validar_ingestao.with_tbox
                for c in g.objects(o, RDF.type):
                    sub.add((o, RDF.type, c))
        rep = val.validate(sub)
        mine = {v7.short(I), "Vuln_Alert_" + n["alert_id"], "Act_Alert_" + n["alert_id"], "Actor_SRC_" + slug(n["ip"])}
        out = [v["message"] for v in rep["violations"] if v["focus"] in mine]
        if n["cvss"] is None and not n["cve"]:
            out.append("sem cvss nem cve: a regra R1 nao pode atribuir risco")
        return sorted(set(out))


# -------------------------------------------------------------------- servidor HTTP
def make_handler(engine, token):
    class H(BaseHTTPRequestHandler):
        server_version = "OntoCSIRT-SOAR/1.0"

        def _send(self, code, obj):
            body = json.dumps(obj, ensure_ascii=False, indent=1).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _auth(self):
            if not token:
                return True
            got = self.headers.get("X-OntoCSIRT-Token", "")
            return hmac.compare_digest(got.encode(), token.encode())

        def do_GET(self):
            if self.path == "/health":
                return self._send(200, {"status": "ok", "kb": os.path.basename(engine.kb_path),
                                        "incidents": engine.n_incidents, "reasoner": engine.reasoner})
            self._send(404, {"error": "use POST /alert ou GET /health"})

        def do_POST(self):
            if self.path not in ("/alert", "/retain"):
                return self._send(404, {"error": "use POST /alert ou POST /retain"})
            if not self._auth():
                return self._send(401, {"error": "token invalido"})
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                n = -1
            if n <= 0 or n > MAX_BODY:
                return self._send(413 if n > MAX_BODY else 400, {"error": "corpo ausente ou maior que %d bytes" % MAX_BODY})
            try:
                alert = json.loads(self.rfile.read(n).decode("utf-8"))
                code, res = engine.handle(alert) if self.path == "/alert" else engine.retain(alert)
            except json.JSONDecodeError:
                code, res = 400, {"error": "JSON invalido"}
            except BadAlert as e:
                code, res = 400, {"error": str(e)}
            except Exception as e:  # noqa: BLE001  (nunca derruba o servico por um alerta)
                code, res = 500, {"error": "falha interna: %s" % type(e).__name__}
            self._send(code, res)

        def log_message(self, fmt, *args):
            sys.stderr.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), fmt % args))

    return H


def main():
    ap = argparse.ArgumentParser(description="Webhook SOAR do OntoCSIRT v7")
    ap.add_argument("--kb", default=v7.TTL, help="base de casos (.ttl); padrao OntoCSIRT_v7.ttl")
    ap.add_argument("--host", default="127.0.0.1"), ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--token", default=os.environ.get("ONTOCSIRT_TOKEN"), help="exige X-OntoCSIRT-Token")
    ap.add_argument("--k", type=int, default=3, help="vizinhos no voto (padrao 3)")
    ap.add_argument("--min-confidence", type=float, default=0.5)
    ap.add_argument("--reasoner", choices=["pellet", "none"], default="pellet",
                    help="none: sem Pellet (mais rapido; sem risco R1 nem R5/R6)")
    ap.add_argument("--once", help="processa um alerta JSON e sai (sem servidor)")
    ap.add_argument("--acquired", default=os.path.join(v7.HERE, "OntoCSIRT_v7_acquired.ttl"),
                    help="dados adquiridos (ontoevo) carregados com a base e destino de POST /retain")
    ap.add_argument("--no-nvd-enrich", action="store_true",
                    help="nao consulta o NVD para CVEs ausentes da base (comportamento anterior)")
    ap.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"), help="chave NVD (50 pedidos/30 s em vez de 5)")
    ap.add_argument("--nvd-cache-hours", type=float, default=24.0, help="validade da cache cache/nvd_<CVE>.json")
    ap.add_argument("--nvd-max-wait", type=float, default=35.0,
                    help="tempo maximo do passo NVD (esperas do limite, pedidos e novas tentativas) antes do fallback")
    a = ap.parse_args()
    enricher = None
    if not a.no_nvd_enrich and a.acquired:
        import nvd_enricher as ne
        enricher = ne.NVDEnricher(kb_path=a.kb, api_key=a.nvd_api_key, ttl=a.nvd_cache_hours * 3600,
                                  max_wait=a.nvd_max_wait)
    eng = Engine(a.kb, a.k, a.min_confidence, a.reasoner, a.acquired, enricher)
    if a.once:
        try:
            code, res = eng.handle(json.loads(a.once))
        except BadAlert as e:
            code, res = 400, {"error": str(e)}
        print(json.dumps(res, ensure_ascii=False, indent=1))
        sys.exit(0 if code == 200 else 1)
    if a.host not in ("127.0.0.1", "localhost") and not a.token:
        print("aviso: a escutar em %s sem --token; qualquer um na rede pode enviar alertas" % a.host, file=sys.stderr)
    srv = ThreadingHTTPServer((a.host, a.port), make_handler(eng, a.token))
    print("OntoCSIRT SOAR webhook em http://%s:%d/alert  (base %s, %d incidentes, raciocinador %s)"
          % (a.host, a.port, os.path.basename(a.kb), eng.n_incidents, a.reasoner))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
