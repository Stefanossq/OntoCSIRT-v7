# -*- coding: utf-8 -*-
"""
catalogs.py - catalogos de referencia usados para VERIFICAR o que o Gemini propoe.

  CWE (MITRE, cwec_latest.xml.zip): nome, abstracao, estado e pais ChildOf na vista de pesquisa 1000.
      Serve para: (1) aceitar so CWEs que existem; (2) ancorar propostas de subcategorias na hierarquia
      oficial (sinal "categoria heterogenea" e "categoria residual").
  ATT&CK Enterprise (MITRE STIX 2.1, versao fixada 16.1 = a do mapeamento CTID KEV->ATT&CK):
      id, nome, taticas (kill_chain_phases), revogado/obsoleto. Sem o STIX, recorre-se as tecnicas que
      aparecem no mapeamento CTID (conjunto menor, mas verificado).

Os ficheiros brutos sao convertidos num JSON compacto em cache/catalogs/ e apagados; os compactos
tem a versao da fonte. Nada aqui chama o Gemini.
"""
import io
import json
import os
import re
import zipfile
import xml.etree.ElementTree as ET

import requests

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIR = os.path.join(HERE, "cache", "catalogs")
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
ATTACK_VERSION = "16.1"
ATTACK_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/"
              "enterprise-attack-%s.json" % ATTACK_VERSION)
CTID_CACHE = os.path.join(HERE, "cache", "ctid_kev_attack.json")
UA = {"User-Agent": "OntoCSIRT-catalogs/1.0 (research prototype)"}

CWE_RX = re.compile(r"^CWE-\d+$")
ATTACK_RX = re.compile(r"^T\d{4}(\.\d{3})?$")


def _path(name):
    return os.path.join(DIR, name)


# ------------------------------------------------------------------ CWE
def build_cwe(xml_bytes):
    root = ET.fromstring(xml_bytes)
    ns = {"c": root.tag.split("}")[0].strip("{")}
    items = {}
    for w in root.iterfind(".//c:Weaknesses/c:Weakness", ns):
        parents = []
        for r in w.iterfind("./c:Related_Weaknesses/c:Related_Weakness", ns):
            if r.get("Nature") == "ChildOf" and r.get("View_ID") == "1000":
                parents.append(("CWE-" + r.get("CWE_ID"), r.get("Ordinal") == "Primary"))
        parents.sort(key=lambda p: (not p[1], int(p[0].split("-")[1])))
        items["CWE-" + w.get("ID")] = {"name": w.get("Name"), "abstraction": w.get("Abstraction"),
                                       "status": w.get("Status"), "parents": [p for p, _ in parents]}
    # CWE <= 4.x: Categories/Category; CWE 5.0 passou a chamar-lhes Groupings/Grouping (p.ex. as categorias do
    # OWASP Top Ten). Sem isto, CWE-1345 era dada como "inexistente" em vez de "categoria (nao mapeavel)".
    for c in list(root.iterfind(".//c:Categories/c:Category", ns)) + list(root.iterfind(".//c:Groupings/c:Grouping", ns)):
        items.setdefault("CWE-" + c.get("ID"), {"name": c.get("Name"), "abstraction": "Category",
                                                "status": c.get("Status"), "parents": [],
                                                "members": ["CWE-" + m.get("CWE_ID") for m in
                                                            c.iterfind("./c:Relationships/c:Has_Member", ns)]})
    views = {}
    for v in root.iterfind(".//c:Views/c:View", ns):
        views["CWE-" + v.get("ID")] = {"name": v.get("Name"), "status": v.get("Status"),
                                       "members": ["CWE-" + m.get("CWE_ID") for m in v.iterfind("./c:Members/c:Has_Member", ns)]}
    return {"source": CWE_URL, "version": root.get("Version"), "date": root.get("Date"), "items": items, "views": views}


def fetch_cwe():
    r = requests.get(CWE_URL, headers=UA, timeout=120)
    r.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        name = next(n for n in z.namelist() if n.endswith(".xml"))
        data = build_cwe(z.read(name))
    os.makedirs(DIR, exist_ok=True)
    with open(_path("cwe.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    return data


# ------------------------------------------------------------------ ATT&CK
def build_attack(stix):
    items, tactics = {}, {}
    for o in stix["objects"]:
        if o.get("type") == "x-mitre-tactic":
            tactics[o["x_mitre_shortname"]] = o["name"]
    for o in stix["objects"]:
        if o.get("type") != "attack-pattern":
            continue
        ext = next((r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        items[ext] = {"name": o["name"], "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])
                                                     if p.get("kill_chain_name") == "mitre-attack"],
                      "revoked": bool(o.get("revoked")), "deprecated": bool(o.get("x_mitre_deprecated")),
                      "subtechnique": bool(o.get("x_mitre_is_subtechnique"))}
    return {"source": ATTACK_URL, "version": ATTACK_VERSION, "tactics": tactics, "items": items}


def fetch_attack():
    r = requests.get(ATTACK_URL, headers=UA, timeout=300)
    r.raise_for_status()
    data = build_attack(r.json())
    os.makedirs(DIR, exist_ok=True)
    with open(_path("attack-%s.json" % ATTACK_VERSION), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    return data


def attack_from_ctid():
    """Catalogo minimo a partir do mapeamento CTID em cache (tecnicas efetivamente usadas no KEV)."""
    with open(CTID_CACHE, encoding="utf-8") as f:
        d = json.load(f)
    items = {}
    for o in d["mapping_objects"]:
        tid = o.get("attack_object_id")
        if tid and ATTACK_RX.match(tid):
            items.setdefault(tid, {"name": o.get("attack_object_name") or tid, "tactics": [], "revoked": False,
                                   "deprecated": False, "subtechnique": "." in tid})
    return {"source": "CTID KEV->ATT&CK (cache)", "version": d["metadata"].get("attack_version"), "tactics": {},
            "items": items}


# ------------------------------------------------------------------ acesso
class Catalogs:
    """Catalogos carregados de cache/catalogs (ou injetados nos testes)."""

    def __init__(self, cwe=None, attack=None):
        self.cwe = cwe if cwe is not None else self._load("cwe.json")
        if attack is None:
            attack = self._load("attack-%s.json" % ATTACK_VERSION)
            if attack is None and os.path.exists(CTID_CACHE):
                attack = attack_from_ctid()
        self.attack = attack

    @staticmethod
    def _load(name):
        p = _path(name)
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        return None

    def status(self):
        return {"cwe": (self.cwe or {}).get("version"), "cwe_entries": len((self.cwe or {}).get("items", {})),
                "attack": (self.attack or {}).get("version"), "attack_source": (self.attack or {}).get("source"),
                "attack_techniques": len((self.attack or {}).get("items", {}))}

    # -- CWE
    def cwe_entry(self, cwe_id):
        if not self.cwe:
            return None
        return self.cwe["items"].get(cwe_id)

    def verify_cwe(self, cwe_id):
        """(ok, motivo). Sem catalogo CWE nao se aceita CWE proposta pelo modelo."""
        if not CWE_RX.match(cwe_id or ""):
            return False, "CWE mal formada"
        if not self.cwe:
            return False, "catalogo CWE ausente (ontocsirt_evolve.py fetch-catalogs)"
        e = self.cwe["items"].get(cwe_id)
        if e is None:
            return False, "%s nao existe no catalogo CWE %s" % (cwe_id, self.cwe.get("version"))
        if e.get("status") == "Deprecated" or e.get("abstraction") == "Category":
            return False, "%s e %s (nao e uma fraqueza mapeavel)" % (cwe_id, "obsoleta" if e.get("status") == "Deprecated" else "categoria")
        return True, "catalogo CWE %s: %s" % (self.cwe.get("version"), e["name"])

    def cwe_ancestors(self, cwe_id, limit=12):
        """Cadeia de antepassados ChildOf (vista 1000), do pai ate ao pilar."""
        out, cur, seen = [], cwe_id, set()
        while cur and cur not in seen and len(out) < limit:
            seen.add(cur)
            e = self.cwe_entry(cur)
            if not e or not e["parents"]:
                break
            cur = e["parents"][0]
            out.append(cur)
        return out

    # -- ATT&CK
    def verify_technique(self, tid):
        if not ATTACK_RX.match(tid or ""):
            return False, "identificador ATT&CK mal formado"
        if not self.attack:
            return False, "catalogo ATT&CK ausente"
        e = self.attack["items"].get(tid)
        if e is None:
            return False, "%s nao existe no catalogo ATT&CK %s (%s)" % (tid, self.attack.get("version"), self.attack.get("source"))
        if e.get("revoked") or e.get("deprecated"):
            return False, "%s revogada/obsoleta no ATT&CK %s" % (tid, self.attack.get("version"))
        return True, "ATT&CK %s: %s" % (self.attack.get("version"), e["name"])

    def technique_name(self, tid):
        e = (self.attack or {}).get("items", {}).get(tid)
        return e["name"] if e else tid

    def technique_tactics(self, tid):
        e = (self.attack or {}).get("items", {}).get(tid)
        return list(e["tactics"]) if e else []
