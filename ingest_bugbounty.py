#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ingest_bugbounty.py - dados reais para o modulo OntoBugBounty (ontology/OntoBugBounty.ttl).

Subcomandos:
  hackerone   programas e escopos da HackerOne (Hacker API) -> ontology/OntoBugBounty_data.ttl
  catalog     regenera o bloco de referencia do modulo a partir de fontes abertas:
                - OWASP Top 10 2021 e 2025: vistas 1344 e 1450 do catalogo CWE (MITRE), que listam as CWEs
                  de cada categoria (o OWASP nao tem API; o MITRE mantem o mapeamento oficial em XML);
                - Bugcrowd VRT (Vulnerability Rating Taxonomy, GitHub): prioridade P1-P5 por variante -> :bountyPayout;
                - CISA KEV + NVD API 2.0: CVEs reais e exploradas de cada padrao, com o CVSS do NVD.
  validate    compoe v7 + extensao + evolucao + modulo + dados e corre SHACL, HermiT, Pellet (regras BB-1/BB-2)
              e as 8 questoes de competencia do v7 (coesao).

HackerOne (https://api.hackerone.com/hacker-resources/):
  * autenticacao HTTP Basic com HACKERONE_USER (nome de utilizador da API) e HACKERONE_TOKEN;
  * GET /v1/hackers/programs e /v1/hackers/programs/{handle}/structured_scopes, paginados com page[size]
    (1-100) e links.next, que se segue ate desaparecer (links.last pode apontar para antes do fim);
    escopos: no maximo 10 000 por paginacao, por isso continua-se com filter[id__gt];
  * limite de leitura de 600 pedidos/min; HTTP 429 -> espera (Retry-After) e nova tentativa;
  * a API NAO publica recompensa minima/maxima: :hasMinBounty/:hasMaxBounty so entram por --bounties
    (ficheiro JSON com a fonte de cada valor, p.ex. a pagina da politica do programa);
  * a API do hacker devolve tambem programas PRIVADOS para que o utilizador foi convidado; a sua
    existencia e o seu escopo sao em geral confidenciais pelos termos do programa. Por omissao so entram
    programas publicos (state == "public_mode"); --include-private muda isso e avisa.
Nada e gravado se o grafo composto nao passar no SHACL (shapes_bugbounty.ttl + restricoes do v7) e no HermiT.

Outras fontes avaliadas (ver README_BugBounty.md): a API do Bugcrowd e para o DONO do programa (token da
organizacao: programas, alvos, submissoes) e nao lista programas publicos; a Hack The Box nao tem API
documentada oficialmente e o seu conteudo sao laboratorios de treino, nao programas de bug bounty.
"""
import argparse
import json
import os
import re
import statistics
import sys
import time
from collections import Counter, defaultdict

import requests
from rdflib import BNode, Graph, Literal, Namespace, URIRef
from rdflib.namespace import OWL, RDF, RDFS, XSD

import ingest_real_cases as ing
import ontocsirt_v7 as v7
import validar_ingestao as val

OC = v7.OC
BB = Namespace("http://www.semanticweb.org/ontocsirt/bugbounty#")
DCT = Namespace("http://purl.org/dc/terms/")
HERE = v7.HERE
ONTO_DIR = os.path.join(HERE, "ontology")
MODULE = os.path.join(ONTO_DIR, "OntoBugBounty.ttl")
SHAPES = os.path.join(ONTO_DIR, "shapes_bugbounty.ttl")
DATA = os.path.join(ONTO_DIR, "OntoBugBounty_data.ttl")
REFINED = os.path.join(ONTO_DIR, "bugbounty_refined.ttl")   # bb-2 (P1-P19)
HUNTER = os.path.join(ONTO_DIR, "hunter_tools.ttl")         # ferramentas do hunter (P20-P22)
EVIDENCE = os.path.join(v7.EVID, "bugbounty.json")
VRT_URL = "https://raw.githubusercontent.com/bugcrowd/vulnerability-rating-taxonomy/master/vulnerability-rating-taxonomy.json"
VRT_CACHE = os.path.join(HERE, "cache", "catalogs", "bugcrowd_vrt.json")
H1_API = "https://api.hackerone.com/v1"
BEGIN, END = "# >>> BEGIN GENERATED: python ingest_bugbounty.py catalog", "# <<< END GENERATED"
UA = {"User-Agent": "OntoCSIRT-bugbounty/1.0 (research prototype)", "Accept": "application/json"}


# =============================================================================================
# Composicao e validacao
# =============================================================================================
def compose(include_data=True, data_path=None, extra=None):
    """v7 (artigo) + extensao + evolucao + modulo de bug bounty (bb-1 + lapidacao bb-2 + ferramentas do hunter)
    (+ dados) num grafo."""
    g = val.with_tbox(Graph())
    g.parse(MODULE, format="turtle")
    for extra_ttl in (REFINED, HUNTER):
        g.parse(extra_ttl, format="turtle")
    p = data_path or DATA
    if include_data and os.path.exists(p):
        g.parse(p, format="turtle")
    for t in extra or ():
        g.add(t)
    return g


def load_shapes():
    sg = val.load_shapes()
    sg.parse(SHAPES, format="turtle")
    return sg


def validate(g, hermit=True, pellet=False):
    """SHACL (v7 + ingestao + evolucao + bug bounty) e, por omissao, HermiT. Devolve um relatorio."""
    from pyshacl import validate as shacl
    conforms, rg, text = shacl(g, shacl_graph=load_shapes(), inference="rdfs", advanced=True,
                               abort_on_first=False, allow_warnings=True)
    if not isinstance(rg, Graph):
        raise RuntimeError("formas SHACL invalidas: %s" % text)
    SH = "http://www.w3.org/ns/shacl#"
    res = []
    for r in rg.subjects(RDF.type, URIRef(SH + "ValidationResult")):
        res.append({"focus": v7.short(rg.value(r, URIRef(SH + "focusNode"))),
                    "severity": v7.short(rg.value(r, URIRef(SH + "resultSeverity"))),
                    "message": str(rg.value(r, URIRef(SH + "resultMessage")))})
    violations = sorted((x for x in res if x["severity"] == "Violation"), key=lambda x: (x["message"], x["focus"]))
    rep = {"conforms": not violations, "violations": violations,
           "warnings": sorted((x for x in res if x["severity"] != "Violation"), key=lambda x: x["focus"]), "triples": len(g)}
    if hermit:
        ok, dt, unsat = v7.run_hermit(g)
        rep["hermit"] = {"consistent": ok, "unsatisfiable_classes": sorted(c for c in unsat if c != "Nothing"),
                         "seconds": round(dt, 2)}
    if pellet:
        ok, dt, ig, _, world = v7.run_pellet(g)
        rep["pellet"] = {"consistent": ok, "seconds": round(dt, 2)}
        rep["_inferred"], rep["_world"] = ig, world
    return rep


def gate_ok(rep):
    h = rep.get("hermit", {"consistent": True, "unsatisfiable_classes": []})
    return rep["conforms"] and h["consistent"] and not h["unsatisfiable_classes"] and rep.get("pellet", {}).get("consistent", True)


def print_report(rep, out=sys.stderr):
    if gate_ok(rep):
        print("OK: SHACL conforme%s (%d triplas)" % (
            "; HermiT consistente, 0 classes insatisfaziveis" if "hermit" in rep else "", rep["triples"]), file=out)
    else:
        print("BLOQUEADO:", file=out)
        for v in rep["violations"][:25]:
            print("  - [%s] %s" % (v["focus"], v["message"]), file=out)
        if len(rep["violations"]) > 25:
            print("  ... mais %d" % (len(rep["violations"]) - 25), file=out)
        h = rep.get("hermit")
        if h and (not h["consistent"] or h["unsatisfiable_classes"]):
            print("  - HermiT: %s %s" % ("INCONSISTENTE" if not h["consistent"] else "", h["unsatisfiable_classes"]), file=out)
    for w in rep.get("warnings", [])[:10]:
        print("  aviso [%s] %s" % (w["focus"], w["message"]), file=out)


# =============================================================================================
# HackerOne
# =============================================================================================
class H1Error(RuntimeError):
    pass


class HackerOneClient:
    def __init__(self, user, token, session=None, sleep=time.sleep, page_size=100, retries=4, base=H1_API):
        if not user or not token:
            raise H1Error("defina HACKERONE_USER e HACKERONE_TOKEN (Settings > API Token na HackerOne)")
        self.auth, self.session, self.sleep = (user, token), session or requests.Session(), sleep
        self.page_size, self.retries, self.base = max(1, min(100, page_size)), retries, base
        self.requests = 0

    def _get(self, url, params=None):
        for attempt in range(1, self.retries + 1):
            self.requests += 1
            try:
                r = self.session.get(url, params=params, auth=self.auth, headers=UA, timeout=(5, 30))
            except (requests.Timeout, requests.ConnectionError) as e:
                if attempt == self.retries:
                    raise H1Error("HackerOne inacessivel: %s" % type(e).__name__) from e
                self.sleep(2 ** attempt)
                continue
            if r.status_code == 200:
                return r.json()
            if r.status_code in (401, 403):
                raise H1Error("HackerOne recusou as credenciais (HTTP %d): confira HACKERONE_USER/HACKERONE_TOKEN"
                              % r.status_code)
            if r.status_code == 429 or r.status_code >= 500:
                wait = float(r.headers.get("Retry-After") or 0) or 2 ** attempt * 5
                if attempt == self.retries:
                    raise H1Error("HackerOne respondeu HTTP %d depois de %d tentativas" % (r.status_code, attempt))
                self.sleep(wait)
                continue
            raise H1Error("HackerOne respondeu HTTP %d em %s" % (r.status_code, url))
        raise H1Error("HackerOne: tentativas esgotadas")

    def paginate(self, path, params=None):
        """Segue links.next ate desaparecer (a documentacao avisa que links.last pode estar antes do fim)."""
        url = self.base + path
        q = dict(params or {})
        q.setdefault("page[size]", self.page_size)
        seen = set()
        while url:
            if url in seen:
                raise H1Error("paginacao em ciclo em %s" % url)
            seen.add(url)
            data = self._get(url, q)
            for item in data.get("data", []):
                yield item
            url = (data.get("links") or {}).get("next")
            q = None                                  # o links.next ja traz a query

    def programs(self):
        return self.paginate("/hackers/programs")

    def structured_scopes(self, handle, cap=10000):
        """Escopos estruturados; acima de `cap` por paginacao continua com filter[id__gt]."""
        cursor = None
        while True:
            params = {"filter[id__gt]": cursor} if cursor else {}
            batch = list(self.paginate("/hackers/programs/%s/structured_scopes" % handle, params))
            for s in batch:
                yield s
            if len(batch) < cap:
                return
            cursor = max(int(s["id"]) for s in batch)


def _slug(s):
    return re.sub(r"[^A-Za-z0-9]+", "_", str(s)).strip("_")[:80]


def _bool(v):
    return Literal(bool(v), datatype=XSD.boolean)


def h1_to_graph(programs, scopes_of, include_private=False, bounties=None, when=None):
    """Programas H1 (lista JSON:API) -> triplas. Devolve (grafo, resumo, recusados)."""
    when = when or time.strftime("%Y-%m-%d")
    g, rejected, kept, nscopes = Graph(), [], [], 0
    bounties = bounties or {}
    for p in programs:
        a = p.get("attributes", {})
        handle, pid = a.get("handle"), p.get("id")
        if not handle or not pid:
            rejected.append({"program": pid or handle, "reason": "registo sem id/handle"})
            continue
        if a.get("state") != "public_mode" and not include_private:
            rejected.append({"program": handle, "reason": "programa nao publico (state=%s): omitido por confidencialidade"
                                                          % a.get("state")})
            continue
        scopes = list(scopes_of(handle))
        if not scopes:
            rejected.append({"program": handle, "reason": "sem escopo estruturado (SHACL exige pelo menos 1 :Scope)"})
            continue
        P = OC["Program_H1_" + _slug(pid)]
        g.add((P, RDF.type, OC.BugBountyProgram))
        g.add((P, RDFS.label, Literal(a.get("name") or handle)))
        g.add((P, OC.programHandle, Literal(handle)))
        g.add((P, OC.hostedOn, OC.Platform_HackerOne))
        if a.get("offers_bounties") is not None:
            g.add((P, OC.offersBounties, _bool(a["offers_bounties"])))
        if a.get("submission_state"):
            g.add((P, OC.submissionState, Literal(a["submission_state"])))
        if a.get("currency"):
            g.add((P, OC.bountyCurrency, Literal(str(a["currency"]).upper())))
        g.add((P, DCT.source, URIRef("https://hackerone.com/" + handle)))
        g.add((P, BB.dataSource, Literal("HackerOne Hacker API /v1/hackers/programs (%s)" % when)))
        b = bounties.get(handle)
        if b:
            if b.get("min") is not None:
                g.add((P, OC.hasMinBounty, Literal(str(b["min"]), datatype=XSD.decimal)))
            if b.get("max") is not None:
                g.add((P, OC.hasMaxBounty, Literal(str(b["max"]), datatype=XSD.decimal)))
            if b.get("currency") and not a.get("currency"):
                g.add((P, OC.bountyCurrency, Literal(str(b["currency"]).upper())))
            g.add((P, BB.derivation, Literal("recompensas: %s" % (b.get("source") or "tabela --bounties sem fonte"))))
        for s in scopes:
            sa = s.get("attributes", {})
            if not sa.get("asset_identifier"):
                continue
            S = OC["Scope_H1_" + _slug(s.get("id"))]
            g.add((P, OC.hasScope, S))
            g.add((S, RDF.type, OC.Scope))
            g.add((S, OC.scopeIdentifier, Literal(sa["asset_identifier"])))
            if sa.get("asset_type"):
                g.add((S, OC.scopeType, Literal(sa["asset_type"])))
            for k, prop in (("eligible_for_bounty", OC.eligibleForBounty), ("eligible_for_submission", OC.eligibleForSubmission)):
                if sa.get(k) is not None:
                    g.add((S, prop, _bool(sa[k])))
            if sa.get("max_severity"):
                g.add((S, OC.maxSeverity, Literal(sa["max_severity"])))
            nscopes += 1
        kept.append(handle)
    g.bind("", OC)
    g.bind("bb", BB)
    g.bind("dcterms", DCT)
    return g, {"programs": len(kept), "scopes": nscopes, "handles": kept}, rejected


def cmd_hackerone(a, client=None):
    client = client or HackerOneClient(os.environ.get("HACKERONE_USER"), os.environ.get("HACKERONE_TOKEN"))
    bounties = {}
    if a.bounties:
        with open(a.bounties, encoding="utf-8") as f:
            bounties = json.load(f)
    if a.include_private:
        print("AVISO: --include-private grava programas privados; confirme que os termos de cada programa o permitem.",
              file=sys.stderr)
    programs = []
    for p in client.programs():
        programs.append(p)
        if a.max_programs and len(programs) >= a.max_programs:
            break
    g, summary, rejected = h1_to_graph(programs, client.structured_scopes, a.include_private, bounties)
    rep = validate(compose(include_data=False, extra=g), hermit=not a.no_hermit)
    print_report(rep)
    out = {"source": "hackerone", "requests": client.requests, "summary": summary, "rejected": rejected,
           "gate": {k: rep.get(k) for k in ("conforms", "violations", "hermit")}, "written": None}
    if gate_ok(rep) and not a.dry_run:
        os.makedirs(os.path.dirname(a.out), exist_ok=True)
        if os.path.exists(a.out) and a.append:
            g.parse(a.out, format="turtle")
        g.serialize(a.out, format="turtle")
        out["written"] = a.out
    _evidence(out)
    print("programas %d, escopos %d, recusados %d, pedidos %d -> %s" % (
        summary["programs"], summary["scopes"], len(rejected), client.requests, out["written"] or "NADA GRAVADO"),
        file=sys.stderr)
    return 0 if (gate_ok(rep) or a.dry_run) else 1


# =============================================================================================
# Catalogo de referencia (OWASP + Bugcrowd VRT + KEV/NVD)
# =============================================================================================
# Curadoria declarada: padrao -> CWEs que visa -> nos do VRT que o classificam. As CWEs seguem o v7
# (AP_* do OntoCSIRT_v7.ttl); AP_XXE e o unico padrao novo.
PATTERNS = {
    "AP_IDOR": {"cwes": ["CWE-639"], "vrt": ["broken_access_control.idor"]},
    "AP_XSS": {"cwes": ["CWE-79"], "vrt": ["cross_site_scripting_xss.reflected", "cross_site_scripting_xss.stored"]},
    "AP_SQLInjection": {"cwes": ["CWE-89"], "vrt": ["server_side_injection.sql_injection"]},
    "AP_SSRF": {"cwes": ["CWE-918"], "vrt": ["server_security_misconfiguration.server_side_request_forgery_ssrf"]},
    "AP_CommandInjection": {"cwes": ["CWE-78", "CWE-77"],
                            "vrt": ["insecure_os_firmware.command_injection", "server_side_injection.remote_code_execution_rce"]},
    "AP_Deserialization": {"cwes": ["CWE-502"], "vrt": ["server_side_injection.remote_code_execution_rce"],
                           "note": "o VRT nao tem classe de desserializacao insegura; estes relatorios sao classificados pelo "
                                   "impacto, tipicamente execucao remota de codigo (server_side_injection.remote_code_execution_rce)"},
    "AP_CSRF": {"cwes": ["CWE-352"], "vrt": ["cross_site_request_forgery_csrf"]},
    "AP_CredentialAbuse": {"cwes": ["CWE-287"], "vrt": ["broken_authentication_and_session_management.authentication_bypass"]},
    "AP_XXE": {"cwes": ["CWE-611"], "vrt": ["server_side_injection.xml_external_entity_injection_xxe"],
               "new": "Injecao de entidade externa XML (XXE)"},
}
OWASP_VIEWS = {"2021": "CWE-1344", "2025": "CWE-1450"}
TIERS = {1: "$$$", 2: "$$$", 3: "$$", 4: "$", 5: "$"}


def load_vrt(refresh=False):
    if os.path.exists(VRT_CACHE) and not refresh:
        with open(VRT_CACHE, encoding="utf-8") as f:
            return json.load(f)
    r = requests.get(VRT_URL, headers=UA, timeout=60)
    r.raise_for_status()
    data = r.json()
    os.makedirs(os.path.dirname(VRT_CACHE), exist_ok=True)
    with open(VRT_CACHE, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return data


def vrt_index(vrt):
    idx = {}

    def walk(n, path):
        for c in n.get("children") or []:
            p = path + [c["id"]]
            idx[".".join(p)] = c
            walk(c, p)
    for top in vrt["content"]:
        idx[top["id"]] = top
        walk(top, [top["id"]])
    return idx


def vrt_priorities(idx, node_id):
    """Prioridades das folhas sob um no do VRT (o proprio no, se tiver prioridade e nao tiver filhos)."""
    n = idx[node_id]
    out = []

    def leaves(x):
        kids = x.get("children") or []
        if not kids:
            if x.get("priority") is not None:
                out.append(int(x["priority"]))
            return
        for k in kids:
            leaves(k)
    leaves(n)
    return out


def payout_for(idx, nodes):
    pr = [p for nd in nodes for p in vrt_priorities(idx, nd)]
    if not pr:
        return None
    typical = statistics.median_low(pr)
    return {"priorities": sorted(pr), "best": min(pr), "typical": typical, "tier": TIERS[typical]}


def severity(score):
    """As mesmas faixas da regra R1 do v7."""
    return "Critical" if score >= 9.0 else "High" if score >= 7.0 else "Medium" if score >= 4.0 else "Low"


def existing_cves():
    """CVEs ja presentes em qualquer base do projeto: nao se reutilizam (o CVSS e funcional no v7)."""
    ids = set()
    for p in (v7.TTL, os.path.join(HERE, "OntoCSIRT_v7_real.ttl"), os.path.join(HERE, "OntoCSIRT_v7_acquired.ttl")):
        if os.path.exists(p):
            ids |= {str(o) for o in Graph().parse(p, format="turtle").objects(None, OC.cveId)}
    return ids


def pick_cves(cwes, kev, nvd, exclude, per_pattern=3):
    """CVEs do KEV com uma das CWEs (mais recentes primeiro), confirmadas pelo NVD (mesma CWE e CVSS 3.x/4.0),
    no maximo uma por fornecedor."""
    chosen, vendors, log = [], set(), []
    cands = sorted((v for v in kev.values() if set(cwes) & set(v.get("cwes", []))), key=lambda v: v["dateAdded"], reverse=True)
    for k in cands:
        if len(chosen) >= per_pattern:
            break
        cve = k["cveID"]
        if cve in exclude or k.get("vendorProject") in vendors:
            continue
        rec = nvd.get(cve)
        cvss = ing.pick_cvss(rec)
        from ontoevo.enrich import nvd_cwes
        nc = nvd_cwes(rec)
        match = [c for c in cwes if c in nc]
        if not cvss or not match:
            log.append({"cve": cve, "reason": "sem CVSS no NVD" if not cvss else "NVD nao confirma a CWE (%s)" % nc})
            continue
        chosen.append({"cve": cve, "cwe": match[0], "cvss": cvss, "vendor": k.get("vendorProject"),
                       "product": k.get("product"), "kev_date": k["dateAdded"]})
        vendors.add(k.get("vendorProject"))
    return chosen, log


def nvd_by_cwe(cwe, end, days=119, session=None, cache_dir=None):
    """CVEs do NVD com a CWE, publicadas numa janela de `days` dias (limite da API: 120) que termina em `end`
    (data do catalogo KEV usado: execucao reprodutivel). Resposta guardada em cache/nvd_cwe/."""
    import datetime as dt
    end_d = dt.datetime.strptime(end, "%Y-%m-%d")
    start_d = end_d - dt.timedelta(days=days)
    cache_dir = cache_dir or os.path.join(HERE, "cache", "nvd_cwe")
    path = os.path.join(cache_dir, "%s_%s_%s.json" % (cwe, start_d.date(), end_d.date()))
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    params = {"cweId": cwe, "pubStartDate": start_d.strftime("%Y-%m-%dT00:00:00.000"),
              "pubEndDate": end_d.strftime("%Y-%m-%dT23:59:59.999"), "resultsPerPage": 200}
    hdr = dict(UA, **({"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}))
    r = (session or requests).get(ing.NVD_URL, params=params, headers=hdr, timeout=60)
    r.raise_for_status()
    recs = [v["cve"] for v in r.json().get("vulnerabilities", [])]
    os.makedirs(cache_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(recs, f)
    time.sleep(0 if os.environ.get("NVD_API_KEY") else 6.5)
    return recs


def pick_nvd_fallback(cwe, end, exclude, vendors, need):
    """Complemento quando o KEV nao chega: CVEs reais com a CWE, analisadas pelo NVD (vulnStatus Analyzed e CVSS
    Primary), mais recentes primeiro, uma por fornecedor. Nao ha confirmacao de exploracao (estao fora do KEV)."""
    from ontoevo.enrich import nvd_cwes, nvd_vendor_product
    out = []
    recs = sorted(nvd_by_cwe(cwe, end), key=lambda c: c.get("published", ""), reverse=True)
    for rec in recs:
        if len(out) >= need:
            break
        cvss = ing.pick_cvss(rec)
        vendor, product = nvd_vendor_product(rec)
        if rec["id"] in exclude or rec.get("vulnStatus") != "Analyzed" or not cvss or cvss["type"] != "Primary":
            continue
        if cwe not in nvd_cwes(rec) or (vendor or rec["id"]) in vendors:
            continue
        out.append({"cve": rec["id"], "cwe": cwe, "cvss": cvss, "vendor": vendor or "?", "product": product or "?",
                    "kev_date": None, "published": rec.get("published", "")[:10]})
        vendors.add(vendor or rec["id"])
    return out


def build_catalog(kev_version, kev, nvd, vrt, cwecat, kb, exclude, per_pattern=3):
    """Grafo do bloco de referencia + resumo. kb: grafo composto (para saber que CWEs/padroes existem)."""
    g = Graph()
    idx = vrt_index(vrt)
    summary = {"vrt_release": (vrt.get("metadata") or {}).get("release_date"), "cwe_version": cwecat.get("version"),
               "kev": kev_version, "patterns": {}, "owasp": {}}
    known_cwes = {str(o) for o in kb.objects(None, OC.cweId)}
    # --- CWEs novas necessarias (so CWE-611 com o PATTERNS atual) ---
    for spec in PATTERNS.values():
        for c in spec["cwes"]:
            if c not in known_cwes:
                W = OC["CWE_" + c.split("-")[1]]
                g.add((W, RDF.type, OC[ing.cwe_category(c, kb)]))
                g.add((W, OC.cweId, Literal(c)))
                g.add((W, RDFS.label, ing.lit("%s %s" % (c, cwecat["items"].get(c, {}).get("name", "")))))
                known_cwes.add(c)
    # --- OWASP Top 10 (vistas do catalogo CWE) ---
    cat_of = defaultdict(list)                  # cwe -> [(edicao, individuo)]
    for edition, view in OWASP_VIEWS.items():
        v = cwecat["views"][view]
        for gid in v["members"]:
            item = cwecat["items"][gid]
            m = re.search(r"(A\d\d):(\d{4})\s*-\s*(.+)$", item["name"])
            code, name = "%s:%s" % (m.group(1), m.group(2)), m.group(3).strip()
            O = OC["OWASP_%s_%s" % (edition, m.group(1))]
            g.add((O, RDF.type, OC.OWASPCategory))
            g.add((O, RDFS.label, Literal("%s - %s" % (code, name))))
            g.add((O, OC.owaspCode, Literal(code)))
            g.add((O, OC.owaspEdition, Literal(edition)))
            g.add((O, OC.cweGroupingId, Literal(gid)))
            g.add((O, BB.dataSource, Literal("MITRE CWE %s, vista %s (%s)" % (cwecat["version"], view, v["name"]))))
            for c in item["members"]:
                cat_of[c].append((edition, O))
                if c in known_cwes:
                    g.add((O, OC.includesWeakness, OC["CWE_" + c.split("-")[1]]))
            summary["owasp"][str(v7.short(O))] = {"code": code, "name": name, "cwes": len(item["members"])}
    # --- padroes ---
    for ap, spec in PATTERNS.items():
        AP = OC[ap]
        if spec.get("new"):
            g.add((AP, RDF.type, OC.AttackPattern))
            g.add((AP, RDFS.label, Literal(spec["new"])))
        chosen = []
        for c in spec["cwes"]:
            got, _ = pick_cves([c], kev, nvd, exclude | {x["cve"] for x in chosen}, per_pattern - len(chosen))
            chosen += got
            if len(chosen) >= per_pattern:
                break
        if len(chosen) < 2:                    # KEV insuficiente (p.ex. IDOR): complemento do NVD por CWE
            kev_end = "%s-%s-%s" % tuple(str(kev_version).split(".")[:3])
            vendors = {x["vendor"] for x in chosen}
            for c in spec["cwes"]:
                chosen += pick_nvd_fallback(c, kev_end, exclude | {x["cve"] for x in chosen}, vendors, 2 - len(chosen))
                if len(chosen) >= 2:
                    break
        if len(chosen) < 2:
            raise RuntimeError("%s: so %d CVE(s) reais confirmadas pelo NVD (minimo 2)" % (ap, len(chosen)))
        for c in spec["cwes"]:
            g.add((AP, OC.targetsCWE, OC["CWE_" + c.split("-")[1]]))
            for _, O in cat_of.get(c, []):
                g.add((AP, OC.owaspCategory, O))
        for x in chosen:
            V = OC["Vuln_" + ing.slug(x["cve"])]
            g.add((V, RDF.type, OC.Vulnerability))
            g.add((V, OC.cveId, Literal(x["cve"])))
            g.add((V, OC.hasWeakness, OC["CWE_" + x["cwe"].split("-")[1]]))
            g.add((V, OC.cvssBaseScore, Literal(str(x["cvss"]["score"]), datatype=XSD.decimal)))
            g.add((V, OC.cvssSource, ing.lit("NVD API 2.0 CVSS %s %s" % (x["cvss"]["version"], x["cvss"]["type"]))))
            if x["cvss"]["C"] in ("HIGH", "LOW", "NONE"):
                g.add((V, OC.confidentialityImpact, Literal(x["cvss"]["C"])))
            g.add((V, RDFS.label, ing.lit("%s %s %s" % (x["cve"], x["vendor"], x["product"]))))
            g.add((V, DCT.source, URIRef("https://nvd.nist.gov/vuln/detail/" + x["cve"])))
            if x["kev_date"]:
                g.add((V, BB.dataSource, Literal("CISA KEV %s (incluida em %s) + NVD API 2.0" % (kev_version, x["kev_date"]))))
            else:
                g.add((V, BB.dataSource, Literal("NVD API 2.0 cweId=%s (publicada em %s; fora do KEV: exploracao "
                                                 "nao confirmada)" % (x["cwe"], x["published"]))))
            g.add((AP, OC.patternExploits, V))
        mean = round(sum(float(x["cvss"]["score"]) for x in chosen) / len(chosen), 2)
        g.add((AP, OC.meanCvss, Literal(str(mean), datatype=XSD.decimal)))
        g.add((AP, OC.hasSeverity, Literal(severity(mean))))
        pay = payout_for(idx, spec["vrt"])
        if pay is None:
            raise RuntimeError("%s: nenhum no do VRT com prioridade (%s)" % (ap, spec["vrt"]))
        g.add((AP, OC.bountyPayout, Literal(pay["tier"])))
        g.add((AP, OC.vrtPriorityTypical, Literal("P%d" % pay["typical"])))
        g.add((AP, OC.vrtPriorityBest, Literal("P%d" % pay["best"])))
        for nd in spec["vrt"]:
            g.add((AP, BB.vrtNode, Literal(nd)))
        n_kev = sum(1 for x in chosen if x["kev_date"])
        g.add((AP, BB.derivation, ing.lit(
            "severidade = faixa R1 da media do CVSS (%.2f) de %d CVEs reais (%d do KEV; %d so do NVD por CWE) com CVSS "
            "do NVD; recompensa = mediana (inferior) das prioridades do Bugcrowd VRT %s %s -> P%d -> %s%s" % (
                mean, len(chosen), n_kev, len(chosen) - n_kev, summary["vrt_release"], pay["priorities"],
                pay["typical"], pay["tier"], ("; nota: " + spec["note"]) if spec.get("note") else ""))))
        summary["patterns"][ap] = {"cves": [(x["cve"], float(x["cvss"]["score"]), x["cwe"]) for x in chosen],
                                   "mean_cvss": mean, "severity": severity(mean), "vrt": pay,
                                   "owasp": sorted(str(v7.short(O)) for c in spec["cwes"] for _, O in cat_of.get(c, []))}
    g.bind("", OC)
    g.bind("bb", BB)
    g.bind("dcterms", DCT)
    return g, summary


def write_generated(g, module=MODULE):
    with open(module, encoding="utf-8") as f:
        text = f.read()
    i, j = text.index(BEGIN), text.index(END)
    body = g.serialize(format="turtle")
    with open(module, "w", encoding="utf-8") as f:
        f.write(text[:i + len(BEGIN)] + "\n# Gerado em %s. Fontes no rdfs:comment/bb:dataSource de cada individuo.\n"
                % time.strftime("%Y-%m-%d") + body + text[j:])


def cmd_catalog(a):
    from ontoevo.catalogs import Catalogs
    cat = Catalogs()
    if not cat.cwe or "views" not in cat.cwe:
        from ontoevo import catalogs
        cat = Catalogs(cwe=catalogs.fetch_cwe())
    kev_version, kev = ing.load_kev(refresh=a.refresh)
    vrt = load_vrt(a.refresh)
    nvd = ing.NVD(api_key=os.environ.get("NVD_API_KEY"))
    kb = val.with_tbox(Graph())
    g, summary = build_catalog(kev_version, kev, nvd, vrt, cat.cwe, kb, existing_cves(), a.per_pattern)
    # valida o modulo com o bloco novo ANTES de o escrever
    module_without = Graph().parse(MODULE, format="turtle")
    trial = val.with_tbox(Graph())
    for t in module_without:
        trial.add(t)
    for t in g:
        trial.add(t)
    rep = validate(trial)
    print_report(rep)
    if not gate_ok(rep):
        return 1
    write_generated(g)
    _evidence({"source": "catalog", "summary": summary})
    for ap, s in summary["patterns"].items():
        print("%-22s %-8s CVSS medio %-5s %-3s VRT %s  %s" % (ap, s["severity"], s["mean_cvss"], s["vrt"]["tier"],
                                                              "P%d" % s["vrt"]["typical"], ", ".join(c for c, _, _ in s["cves"])))
    return 0


# =============================================================================================
# Validacao do conjunto
# =============================================================================================
def rule_results(ig):
    elite = sorted(v7.short(s) for s in ig.subjects(RDF.type, OC.EliteResearcher))
    authorized = sorted(v7.short(s) for s in ig.subjects(RDF.type, OC.AuthorizedResearcher))
    priority = sorted(v7.short(s) for s, o in ig.subject_objects(OC.status) if str(o) == "Priority")
    cves = sorted(v7.short(s) for s in ig.subjects(RDF.type, OC.CVE))
    return {"EliteResearcher": elite, "AuthorizedResearcher": authorized, "PriorityReports": priority, "CVE_count": len(cves)}


def cmd_validate(a):
    g = compose(include_data=not a.no_data)
    rep = validate(g, hermit=True, pellet=True)
    print_report(rep)
    ig = rep.pop("_inferred", None)
    rep.pop("_world", None)
    out = {"gate": {k: rep.get(k) for k in ("conforms", "violations", "warnings", "hermit", "pellet", "triples")}}
    if ig is not None:
        out["rules"] = rule_results(ig)
        # aviso de mundo fechado sobre o grafo INFERIDO: nivel declarado vs classe inferida
        out["skill_vs_inferred"] = [r for r in out["rules"]["EliteResearcher"]
                                    if str(g.value(OC[r], OC.hasSkillLevel)) == "Junior"]
        cq = sum({x[0] for x in v7.q(ig, s)} == exp for _, _, s, exp in v7.CQS)
        out["v7_competency_questions"] = "%d/%d" % (cq, len(v7.CQS))
        print(json.dumps({k: out[k] for k in ("rules", "skill_vs_inferred", "v7_competency_questions")}, ensure_ascii=False, indent=1))
    _evidence(out, "validate")
    return 0 if gate_ok(rep) else 1


def _evidence(obj, key=None):
    os.makedirs(os.path.dirname(EVIDENCE), exist_ok=True)
    cur = {}
    if os.path.exists(EVIDENCE):
        with open(EVIDENCE, encoding="utf-8") as f:
            cur = json.load(f)
    cur[key or obj.get("source", "run")] = dict(obj, at=time.strftime("%Y-%m-%dT%H:%M:%S"))
    with open(EVIDENCE, "w", encoding="utf-8") as f:
        json.dump(cur, f, indent=1, ensure_ascii=False, default=str)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("hackerone", help="programas e escopos da HackerOne -> ontology/OntoBugBounty_data.ttl")
    p.add_argument("--out", default=DATA)
    p.add_argument("--max-programs", type=int, default=0, help="0 = todos")
    p.add_argument("--include-private", action="store_true", help="inclui programas privados (confidenciais)")
    p.add_argument("--bounties", help="JSON {handle: {min, max, currency, source}} (a API nao publica recompensas)")
    p.add_argument("--append", action="store_true", help="junta aos dados ja gravados em vez de substituir")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--no-hermit", action="store_true")
    p.set_defaults(fn=cmd_hackerone)
    p = sub.add_parser("catalog", help="regenera o bloco de referencia do modulo (OWASP, VRT, KEV/NVD)")
    p.add_argument("--per-pattern", type=int, default=3)
    p.add_argument("--refresh", action="store_true", help="volta a baixar KEV e VRT")
    p.set_defaults(fn=cmd_catalog)
    p = sub.add_parser("validate", help="SHACL + HermiT + Pellet (BB-1/BB-2) + CQs do v7")
    p.add_argument("--no-data", action="store_true")
    p.set_defaults(fn=cmd_validate)
    a = ap.parse_args()
    try:
        sys.exit(a.fn(a))
    except H1Error as e:
        print("erro: %s" % e, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
