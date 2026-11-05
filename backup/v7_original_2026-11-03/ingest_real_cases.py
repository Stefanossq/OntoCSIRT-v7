#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ingest_real_cases.py - ETL de casos reais para o OntoCSIRT v7.

Fontes (todas publicas):
  * CISA KEV ............ CVEs com exploracao confirmada (CWE, fornecedor/produto, requiredAction, data)
  * CTID Mappings Explorer (KEV -> MITRE ATT&CK) ... tecnica de exploracao de cada CVE
  * NVD API 2.0 ......... CVSS e impactos C/I/A (o KEV nao traz CVSS)

O que o ETL faz, por CVE selecionada:
  Vulnerability (cveId, CWE, CVSS do NVD) -> AttackPattern (tecnica ATT&CK) -> ThreatAction
  -> Incident (ator VERIS Unknown, ativo por heuristica de produto, atributo CIA pelo CVSS)
  -> Case (hasSolution = acao gerada pela categoria do CWE, com proveniencia declarada).
Depois chama validar_ingestao.gate(): SHACL (+Pellet opcional). So grava se passar.

AVISO METODOLOGICO (vai tambem para o relatorio JSON):
  - Um registo do KEV e um aviso de vulnerabilidade explorada, NAO um incidente com desfecho.
    Os "casos" gerados sao casos-modelo derivados de dados reais, nao historicos de um CSIRT.
  - hasSolution vem de uma politica (categoria do CWE -> acao). Usar esses rotulos como verdade
    num LOOCV e circular: a similaridade usa o proprio CWE. Use --label kev para rotulos
    independentes (normalizacao do requiredAction do KEV), sabendo que sao quase constantes.

Uso tipico:
  python ingest_real_cases.py --limit 40                         # baixa tudo da internet (NVD a 5 req/30 s)
  python ingest_real_cases.py --limit 40 --nvd-api-key KEY       # 50 req/30 s
  python ingest_real_cases.py --kev-file kev.json --ctid-file map.json --nvd-mirror ./nvd-json-data-feeds
  python ingest_real_cases.py --mode append --pellet --out OntoCSIRT_v7_real.ttl

Este produto usa dados da API do NVD, mas nao e endossado nem certificado pelo NVD.
"""
import argparse
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict

import requests
from rdflib import BNode, Graph, Literal, Namespace, URIRef
from rdflib.collection import Collection
from rdflib.namespace import OWL, RDF, RDFS, XSD

import ontocsirt_v7 as v7
import validar_ingestao as val

OC = v7.OC
DCT = Namespace("http://purl.org/dc/terms/")
HERE = v7.HERE
CACHE = os.path.join(HERE, "cache")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CTID_URL = ("https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/"
            "mappings/kev/attack-16.1/kev-07.28.2025/enterprise/kev-07.28.2025_attack-16.1-enterprise.json")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = {"User-Agent": "OntoCSIRT-ingest/1.0 (research prototype)"}

# --------------------------------------------------------------------------------------------
# 1. Tabelas de mapeamento (decisoes de modelagem; documentadas e versionadas)
# --------------------------------------------------------------------------------------------
# CWE -> categoria do OntoCSIRT. As 6 primeiras categorias e os seus CWE vem do v7;
# o resto acrescenta os CWE mais frequentes no KEV. Nao reproduz a hierarquia oficial da CWE.
CWE_CATEGORY = {
    "InjectionWeakness": [77, 78, 89, 74, 94, 917, 1336, 88, 95, 91],
    "WebClientWeakness": [79, 352, 601, 1021],
    "AccessControlWeakness": [639, 862, 863, 284, 285, 269, 732, 276, 281, 266, 250, 668],
    "AuthenticationWeakness": [287, 798, 306, 288, 290, 294, 307, 521, 522, 384, 1390, 620, 640],
    "ResourceHandlingWeakness": [22, 23, 36, 434, 502, 59, 61, 611, 73, 98, 552, 427, 426],
    "RequestForgeryWeakness": [918],
    "MemorySafetyWeakness": [416, 787, 119, 120, 121, 122, 125, 190, 191, 843, 476, 415, 822, 823, 824, 908, 704, 763, 680, 131],
}
CWE2CAT = {"CWE-%d" % n: cat for cat, ns in CWE_CATEGORY.items() for n in ns}


def cwe_category(cwe):
    return CWE2CAT.get(cwe, "OtherWeakness")


# Politica de resposta = a MESMA do v7 (secao 7 do .ttl), estendida as duas categorias novas.
def policy_action(category, attribute):
    if category == "InjectionWeakness":
        return "CoA_Isolate" if attribute == "State_Confidentiality" else "CoA_Patch"
    return {"WebClientWeakness": "CoA_WAFRule", "AccessControlWeakness": "CoA_AccessControlFix",
            "AuthenticationWeakness": "CoA_RotateCredentials", "ResourceHandlingWeakness": "CoA_Patch",
            "RequestForgeryWeakness": "CoA_Segment", "MemorySafetyWeakness": "CoA_Patch",
            "OtherWeakness": "CoA_Patch"}[category]


# requiredAction do KEV (texto livre) -> acao. A ordem importa: fim de vida antes de "update".
def kev_action(text):
    t = (text or "").lower()
    # "discontinue use ... if mitigations are unavailable" e um recurso de ultimo caso no texto padrao
    # do KEV, nao um fim de vida; so "end-of-life"/"EoL" contam como descontinuar.
    if re.search(r"end-of-life|end of life|\beol\b", t):
        return "CoA_Decommission"
    if "mitigat" in t:
        return "CoA_ApplyMitigation"
    if re.search(r"update|patch|upgrade", t):
        return "CoA_Patch"
    return "CoA_ApplyMitigation"


# Fornecedor+produto -> tipo de ativo. Heuristica explicita: a regra que disparou fica no grafo.
ASSET_RULES = [
    ("Gateway", r"vpn|firewall|gateway|router|switch|asa\b|fortios|fortigate|fortiproxy|pan-os|globalprotect|netscaler|"
                r"citrix adc|big-ip|pulse connect|ivanti connect|sonicwall|sma\b|zyxel|draytek|f5|juniper|junos|ios xe|"
                r"secure access|load balancer|edge|sd-wan|access point|wireless|nas\b|qnap|synology|camera|dvr|nvr"),
    ("Database", r"database|sql server|mysql|postgres|oracle db|mongodb|redis|elasticsearch|db2"),
    ("Workstation", r"windows(?! server)|office|word|excel|outlook|chrome|chromium|firefox|safari|webkit|internet explorer|"
                    r"edge browser|acrobat|reader|flash|java se|ios\b|ipados|macos|android|pixel|win32k|kernel-mode driver|"
                    r"desktop|client|7-zip|winrar|webview"),
]


def asset_type(vendor, product):
    s = ("%s %s" % (vendor, product)).lower()
    for cls, rx in ASSET_RULES:
        m = re.search(rx, s)
        if m:
            return cls, "heuristica: '%s' -> %s" % (m.group(0).strip(), cls)
    return "Server", "heuristica: sem regra -> Server (padrao)"


# --------------------------------------------------------------------------------------------
# 2. Extracao (com cache local: rede so na primeira vez; reprodutivel depois)
# --------------------------------------------------------------------------------------------
def fetch_json(url, cache_name, local=None, refresh=False, params=None, headers=None):
    if local:
        with open(local, encoding="utf-8") as f:
            return json.load(f)
    path = os.path.join(CACHE, cache_name)
    if os.path.exists(path) and not refresh:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    r = requests.get(url, params=params, headers={**UA, **(headers or {})}, timeout=60)
    r.raise_for_status()
    data = r.json()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return data


def load_kev(local=None, refresh=False):
    d = fetch_json(KEV_URL, "kev.json", local, refresh)
    return d.get("catalogVersion"), {v["cveID"]: v for v in d["vulnerabilities"]}


def load_ctid(local=None, refresh=False):
    """cve -> {'exploit': [(tid, nome)], 'impact': [(tid, nome)]} a partir do mapeamento CTID."""
    d = fetch_json(CTID_URL, "ctid_kev_attack.json", local, refresh)
    out = defaultdict(lambda: {"exploit": [], "impact": []})
    for o in d["mapping_objects"]:
        if not o.get("attack_object_id"):
            continue
        k = "exploit" if o["mapping_type"] == "exploitation_technique" else "impact"
        pair = (o["attack_object_id"], o.get("attack_object_name") or o["attack_object_id"])
        if pair not in out[o["capability_id"]][k]:
            out[o["capability_id"]][k].append(pair)
    return d.get("metadata", {}), out


class NVD:
    """Le registos CVE do NVD: espelho local (fkie-cad/nvd-json-data-feeds) > cache > API 2.0."""

    def __init__(self, mirror=None, api_key=None, refresh=False):
        self.mirror, self.key, self.refresh = mirror, api_key, refresh
        self.delay = 0.7 if api_key else 6.5          # limites publicos: 50 ou 5 pedidos / 30 s
        self.last = 0.0
        self.calls = 0

    def get(self, cve):
        if self.mirror:
            year, num = cve.split("-")[1], cve.split("-")[2]
            p = os.path.join(self.mirror, "CVE-%s" % year, "CVE-%s-%sxx" % (year, num[:-2]), cve + ".json")
            if os.path.exists(p):
                with open(p, encoding="utf-8") as f:
                    return json.load(f)
            return None
        path = os.path.join(CACHE, "nvd", cve + ".json")
        if os.path.exists(path) and not self.refresh:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        wait = self.delay - (time.time() - self.last)
        if wait > 0:
            time.sleep(wait)
        hdr = {"apiKey": self.key} if self.key else {}
        for attempt in range(3):
            self.last = time.time()
            r = requests.get(NVD_URL, params={"cveId": cve}, headers={**UA, **hdr}, timeout=60)
            if r.status_code in (403, 429, 503):           # limite excedido: espera e tenta de novo
                time.sleep(30 * (attempt + 1))
                continue
            r.raise_for_status()
            break
        else:
            return None
        self.calls += 1
        vulns = r.json().get("vulnerabilities", [])
        rec = vulns[0]["cve"] if vulns else None
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rec, f)
        return rec


def pick_cvss(rec):
    """CVSS mais confiavel disponivel: 3.1 > 3.0 > 4.0, Primary (NVD) > Secondary (CNA). v2 nao e aceite."""
    m = (rec or {}).get("metrics", {})
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV40", "4.0")):
        rows = m.get(key) or []
        for kind in ("Primary", "Secondary"):
            for row in rows:
                if row.get("type") == kind:
                    d = row["cvssData"]
                    imp = lambda k: d.get(k) or d.get("vuln" + k[0].upper() + k[1:])  # noqa: E731  (v4 usa vulnXxx)
                    return {"score": d["baseScore"], "version": ver, "type": kind, "source": row.get("source"),
                            "C": imp("confidentialityImpact"), "I": imp("integrityImpact"), "A": imp("availabilityImpact")}
    return None


def attribute_from_cvss(c):
    """Atributo VERIS afetado: o primeiro de C, I, A com impacto HIGH; senao o maior impacto."""
    rank = {"HIGH": 2, "LOW": 1, "NONE": 0, None: -1}
    for k, st in (("C", "State_Confidentiality"), ("I", "State_Integrity"), ("A", "State_Availability")):
        if c[k] == "HIGH":
            return st
    best = max((("C", "State_Confidentiality"), ("I", "State_Integrity"), ("A", "State_Availability")),
               key=lambda kv: rank.get(c[kv[0]], -1))
    return best[1]


# --------------------------------------------------------------------------------------------
# 3. Selecao de CVEs
# --------------------------------------------------------------------------------------------
def candidates(kev, ctid):
    out = []
    for cve, v in kev.items():
        cwes = [c for c in v.get("cwes", []) if re.match(r"^CWE-\d+$", c)]
        if cwes and ctid.get(cve, {}).get("exploit"):
            out.append((cve, cwes))
    return out


def select(kev, ctid, limit, strategy):
    """'stratified': alterna entre categorias de CWE (mais recentes primeiro) para a base nao ser
    dominada por uma so categoria; 'recent': so por data de inclusao no KEV."""
    cands = sorted(candidates(kev, ctid), key=lambda x: kev[x[0]]["dateAdded"], reverse=True)
    if strategy == "recent":
        return [c for c, _ in cands][:limit]
    buckets = defaultdict(list)
    for cve, cwes in cands:
        buckets[cwe_category(cwes[0])].append(cve)
    order, picked = sorted(buckets), []
    while len(picked) < limit and any(buckets.values()):
        for cat in order:
            if buckets[cat] and len(picked) < limit:
                picked.append(buckets[cat].pop(0))
    return picked


# --------------------------------------------------------------------------------------------
# 4. Transformacao e carga no grafo
# --------------------------------------------------------------------------------------------
def slug(s):
    return re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_")


def lit(s):
    # O leitor da saida do Pellet no Owlready2 parte literais com virgulas (ver artigo, secao 6):
    # todos os literais de dados ingeridos ficam sem virgulas.
    return Literal(re.sub(r"\s*,\s*", "; ", str(s)).strip())


def remove_all_different(g):
    for b in list(g.subjects(RDF.type, OWL.AllDifferent)):
        lst = g.value(b, OWL.distinctMembers)
        if lst is not None:
            Collection(g, lst).clear()
            g.remove((b, OWL.distinctMembers, lst))
        for t in list(g.triples((b, None, None))):
            g.remove(t)


def add_all_different(g):
    incs = sorted(set(g.subjects(RDF.type, OC.Incident)), key=str)
    b, lst = BNode(), BNode()
    Collection(g, lst, incs)
    g.add((b, RDF.type, OWL.AllDifferent))
    g.add((b, OWL.distinctMembers, lst))
    return len(incs)


def remove_synthetic(g):
    """Retira os 18 casos sinteticos do v7 (vulnerabilidade sem cveId) e tudo o que so eles usam.
    Os 6 casos herdados, que tem CVE real, ficam."""
    synthetic = []
    for inc in g.subjects(RDF.type, OC.Incident):
        vulns = list(g.objects(inc, OC.involvesVulnerability))
        if vulns and all(g.value(v, OC.cveId) is None for v in vulns):
            synthetic.append(inc)
    # primeiro identifica todos, depois apaga: varios sinteticos partilham a mesma Vuln_Lxx
    nodes = set()
    for inc in synthetic:
        nodes |= {inc, *g.objects(inc, OC.hasAction), *g.objects(inc, OC.involvesVulnerability),
                  *g.subjects(OC.hasProblem, inc)}
    for n in nodes:
        for t in list(g.triples((n, None, None))) + list(g.triples((None, None, n))):
            g.remove(t)
    removed = [v7.short(i) for i in synthetic]
    return sorted(removed)


def add_case(g, cve, k, techniques, rec, cvss, label_mode):
    """Converte um registo (KEV + CTID + NVD) em triplas. Devolve um resumo do caso."""
    sid = slug(cve)
    cwes = [c for c in k.get("cwes", []) if re.match(r"^CWE-\d+$", c)]
    cwe = cwes[0]
    cat = cwe_category(cwe)
    W = OC["CWE_" + cwe.split("-")[1]]
    if (W, OC.cweId, None) not in g:                                  # CWE novo na base
        g.add((W, RDF.type, OC[cat]))
        g.add((W, OC.cweId, Literal(cwe)))
        g.add((W, RDFS.label, Literal(cwe)))

    # Vulnerability
    V = OC["Vuln_" + sid]
    g.add((V, RDF.type, OC.Vulnerability))
    g.add((V, OC.cveId, Literal(cve)))
    g.add((V, OC.hasWeakness, W))
    if len(cwes) > 1:
        g.add((V, OC.otherCweIds, Literal(" ".join(cwes[1:]))))
    g.add((V, OC.cvssBaseScore, Literal(str(cvss["score"]), datatype=XSD.decimal)))
    g.add((V, OC.cvssSource, lit("NVD API 2.0 CVSS %s %s" % (cvss["version"], cvss["type"]))))
    if cvss["C"] in ("HIGH", "LOW", "NONE"):
        g.add((V, OC.confidentialityImpact, Literal(cvss["C"])))
    g.add((V, OC.kevDateAdded, Literal(k["dateAdded"], datatype=XSD.date)))
    g.add((V, OC.knownRansomwareUse, Literal(k.get("knownRansomwareCampaignUse", "Unknown"))))
    g.add((V, DCT.source, URIRef("https://nvd.nist.gov/vuln/detail/" + cve)))

    # AttackPattern (ATT&CK) e ThreatAction: uma tecnica na acao (SHACL exige exatamente 1);
    # prefere T1190 (exploracao de aplicacao exposta), as restantes ficam em mappedTechnique.
    techs = sorted(techniques, key=lambda t: (t[0] != "T1190", t[0]))
    for tid, name in techs:
        AP = OC["AP_" + slug(tid)]
        if (AP, OC.attackId, None) not in g:
            g.add((AP, RDF.type, OC.AttackPattern))
            g.add((AP, OC.attackId, Literal(tid)))
            g.add((AP, RDFS.label, lit("%s %s (MITRE ATT&CK)" % (tid, name))))
            g.add((AP, DCT.source, URIRef("https://attack.mitre.org/techniques/" + tid.replace(".", "/"))))
    main_ap = OC["AP_" + slug(techs[0][0])]
    for tid, _ in techs[1:]:
        g.add((V, OC.mappedTechnique, OC["AP_" + slug(tid)]))
    A = OC["Act_" + sid]
    g.add((A, RDF.type, OC.ThreatAction))
    g.add((A, OC.instantiatesPattern, main_ap))
    g.add((A, OC.exploits, V))

    # Asset (um individuo por fornecedor+produto; o mesmo produto em varias CVEs e o mesmo ativo)
    vendor, product = k.get("vendorProject", "?"), k.get("product", "?")
    cls, evidence = asset_type(vendor, product)
    AS = OC["Asset_" + slug(vendor + "_" + product)]
    if (AS, RDF.type, None) not in g:
        g.add((AS, RDF.type, OC[cls]))
        g.add((AS, RDFS.label, lit("%s %s" % (vendor, product))))
        g.add((AS, OC.vendorProduct, lit("%s %s" % (vendor, product))))
        g.add((AS, OC.assetTypeEvidence, lit(evidence)))

    # Ator: desconhecido e proprio de cada caso (o KEV nao identifica atores)
    AC = OC["Actor_Unknown_" + sid]
    g.add((AC, RDF.type, OC.UnknownActor))
    g.add((AC, RDFS.label, Literal("Ator desconhecido (KEV %s)" % cve)))

    attr = attribute_from_cvss(cvss)
    I = OC["Incident_" + sid]
    g.add((I, RDF.type, OC.Incident))
    g.add((I, RDFS.label, lit("Exploracao conhecida de %s em %s %s (CISA KEV)" % (cve, vendor, product))))
    for p, o in ((OC.hasActor, AC), (OC.hasAction, A), (OC.hasAsset, AS), (OC.hasAttribute, OC[attr]),
                 (OC.involvesVulnerability, V)):
        g.add((I, p, o))
    g.add((I, DCT.source, URIRef(KEV_URL)))

    # Case: hasSolution segundo --label; a outra acao fica registada para comparacao
    pol, kev_a = policy_action(cat, attr), kev_action(k.get("requiredAction"))
    C = OC["Case_" + sid]
    g.add((C, RDF.type, OC.Case))
    g.add((C, OC.hasProblem, I))
    g.add((C, OC.hasSolution, OC[pol if label_mode == "cwe-policy" else kev_a]))
    g.add((C, OC.solutionProvenance, Literal("policy:cwe-category-v1" if label_mode == "cwe-policy" else "kev:requiredAction")))
    g.add((C, OC.kevSolution, OC[kev_a]))
    g.add((C, OC.kevRequiredAction, lit(k.get("requiredAction", ""))))
    return {"cve": cve, "cwe": cwe, "category": cat, "technique": techs[0][0], "asset": v7.short(AS), "asset_type": cls,
            "cvss": cvss["score"], "cvss_version": cvss["version"], "attribute": attr,
            "policy_action": pol, "kev_action": kev_a}


def leakage_check(g):
    """LOOCV rapido (sem Pellet) da recuperacao do v7 sobre a base ingerida, contra a classe majoritaria.
    Serve para MOSTRAR a circularidade: com --label cwe-policy o rotulo e funcao do CWE e o Acc@1 sobe
    artificialmente; com --label kev os rotulos sao independentes mas quase constantes."""
    from soar_webhook import features            # FEATURE_Q com UnknownActor
    F = features(g)
    hit = maj = 0
    for i, f in F.items():
        rest = {j: x for j, x in F.items() if j != i}
        best = max(rest.items(), key=lambda kv: (v7.sim(f, kv[1]), kv[0]))
        hit += best[1]["sol"] == f["sol"]
        maj += Counter(x["sol"] for x in rest.values()).most_common(1)[0][0] == f["sol"]
    n = len(F) or 1
    return {"n_cases": len(F), "acc1_similarity": round(hit / n, 3), "acc1_majority": round(maj / n, 3)}


# --------------------------------------------------------------------------------------------
# 5. Orquestracao
# --------------------------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="ETL CISA KEV + CTID ATT&CK + NVD -> casos do OntoCSIRT v7")
    ap.add_argument("--limit", type=int, default=40, help="numero de CVEs a ingerir (padrao 40)")
    ap.add_argument("--strategy", choices=["stratified", "recent"], default="stratified")
    ap.add_argument("--mode", choices=["replace-synthetic", "append"], default="replace-synthetic",
                    help="replace-synthetic: retira os 18 casos sinteticos e mantem os 6 herdados com CVE real")
    ap.add_argument("--label", choices=["cwe-policy", "kev"], default="cwe-policy",
                    help="origem de hasSolution (ver aviso metodologico no topo)")
    ap.add_argument("--kev-file"), ap.add_argument("--ctid-file")
    ap.add_argument("--nvd-mirror", help="clone local de github.com/fkie-cad/nvd-json-data-feeds (sem rede)")
    ap.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"))
    ap.add_argument("--refresh", action="store_true", help="ignora a cache local e volta a baixar")
    ap.add_argument("--pellet", action="store_true", help="portao de consistencia com o Pellet (mais lento)")
    ap.add_argument("--out", default=os.path.join(HERE, "OntoCSIRT_v7_real.ttl"))
    ap.add_argument("--staging", default=os.path.join(HERE, "staging_ingest.ttl"))
    a = ap.parse_args()

    kev_version, kev = load_kev(a.kev_file, a.refresh)
    ctid_meta, ctid = load_ctid(a.ctid_file, a.refresh)
    print("KEV %s: %d CVEs | CTID ATT&CK %s: %d CVEs mapeadas | candidatas (CWE + tecnica): %d"
          % (kev_version, len(kev), ctid_meta.get("attack_version"), len(ctid), len(candidates(kev, ctid))))

    g = v7.base_graph()
    g.parse(val.EXT, format="turtle")
    removed = remove_synthetic(g) if a.mode == "replace-synthetic" else []
    remove_all_different(g)
    existing = {str(o) for o in g.objects(None, OC.cveId)}

    nvd = NVD(a.nvd_mirror, a.nvd_api_key, a.refresh)
    pool = select(kev, ctid, a.limit * 3, a.strategy)     # folga para as rejeitadas
    cases, rejected = [], []
    for cve in pool:
        if len(cases) >= a.limit:
            break
        if cve in existing:
            rejected.append({"cve": cve, "reason": "ja presente na base (caso herdado do v7)"})
            continue
        rec = nvd.get(cve)
        cvss = pick_cvss(rec)
        if cvss is None:
            rejected.append({"cve": cve, "reason": "sem registo NVD ou sem CVSS 3.x/4.0"})
            continue
        cases.append(add_case(g, cve, kev[cve], ctid[cve]["exploit"], rec, cvss, a.label))
        print("  + %-16s %-8s %-26s %-9s CVSS %-4s -> %s" % (cve, cases[-1]["cwe"], cases[-1]["category"],
              cases[-1]["technique"], cvss["score"], cases[-1]["policy_action"]))
    n_inc = add_all_different(g)
    g.serialize(a.staging, format="turtle")

    agree = sum(c["policy_action"] == c["kev_action"] for c in cases)
    report = {
        "sources": {"kev_catalogVersion": kev_version, "ctid_attack_version": ctid_meta.get("attack_version"),
                    "ctid_mapping_version": ctid_meta.get("mapping_framework_version"),
                    "nvd": "mirror:" + a.nvd_mirror if a.nvd_mirror else "API 2.0 (cache em cache/nvd)"},
        "params": vars(a) | {"nvd_api_key": bool(a.nvd_api_key)},
        "removed_synthetic": removed, "ingested": len(cases), "rejected": rejected, "incidents_total": n_inc,
        "label_distribution": dict(Counter(c["policy_action"] if a.label == "cwe-policy" else c["kev_action"] for c in cases)),
        "category_distribution": dict(Counter(c["category"] for c in cases)),
        "asset_type_distribution": dict(Counter(c["asset_type"] for c in cases)),
        "policy_vs_kev_agreement": "%d/%d" % (agree, len(cases)),
        "leakage_check_loocv": leakage_check(g),
        "caveats": [
            "Registos KEV sao avisos de exploracao, nao incidentes com desfecho observado.",
            "hasSolution e %s; nao e decisao de um analista." % (
                "sugestao da politica CWE->acao" if a.label == "cwe-policy" else "normalizacao do requiredAction do KEV"),
            "Com --label cwe-policy, avaliar a recuperacao contra estes rotulos e circular (o CWE e atributo e rotulo).",
            "Ator = VERIS Unknown (KEV nao identifica atores); tipo de ativo por heuristica de produto.",
        ],
        "cases": cases,
    }
    os.makedirs(v7.EVID, exist_ok=True)
    with open(os.path.join(v7.EVID, "ingest.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print("ingeridos %d, rejeitados %d, sinteticos retirados %d, incidentes na base %d"
          % (len(cases), len(rejected), len(removed), n_inc))
    print("politica CWE vs acao do KEV concordam em %s casos" % report["policy_vs_kev_agreement"])
    lk = report["leakage_check_loocv"]
    print("LOOCV de controlo (rotulo=%s): Acc@1 similaridade %.2f vs maioria %.2f  [com cwe-policy e circular]"
          % (a.label, lk["acc1_similarity"], lk["acc1_majority"]))
    print("staging: %s ; relatorio: evidence_v7/ingest.json\n-- validacao --" % a.staging)
    sys.exit(val.gate(g, a.out, a.pellet, os.path.join(v7.EVID, "ingest_validation.json")))


if __name__ == "__main__":
    main()
