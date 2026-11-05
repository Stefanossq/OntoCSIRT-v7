"""ingest_bugbounty.py hackerone - sem rede: sessao HTTP falsa com a estrutura documentada da Hacker API
(https://api.hackerone.com/hacker-resources/): JSON:API com data[].attributes e links.next."""
import json
import os
from types import SimpleNamespace

import pytest
from rdflib import Graph

import ingest_bugbounty as bb

OC = bb.OC
BASE = bb.H1_API


def program(pid, handle, state="public_mode", offers=True, currency="usd"):
    return {"id": str(pid), "type": "program",
            "attributes": {"handle": handle, "name": handle.title() + " Security", "currency": currency,
                           "submission_state": "open", "state": state, "offers_bounties": offers,
                           "open_scope": False, "policy": "texto longo da politica, que nao e gravado"}}


def scope(sid, ident, atype="URL", bounty=True):
    return {"id": str(sid), "type": "structured-scope",
            "attributes": {"asset_type": atype, "asset_identifier": ident, "eligible_for_bounty": bounty,
                           "eligible_for_submission": True, "max_severity": "critical", "instruction": None}}


class Resp:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body, headers or {}

    def json(self):
        return self._body


class FakeH1:
    """Rotas: programas em 2 paginas (links.next com URL completo); escopos por handle."""

    def __init__(self, first=None):
        self.calls, self.first = [], list(first or [])
        self.scopes = {"acme": [scope(11, "app.acme.example"), scope(12, "*.acme.example", "WILDCARD", False)],
                       "beta": [], "secret": [scope(31, "internal.secret.example")]}

    def get(self, url, params=None, auth=None, headers=None, timeout=None):
        self.calls.append({"url": url, "params": params, "auth": auth})
        if self.first:
            return self.first.pop(0)
        if url.endswith("/hackers/programs"):
            return Resp(200, {"data": [program(1, "acme"), program(2, "beta")],
                              "links": {"next": BASE + "/hackers/programs?page%5Bnumber%5D=2&page%5Bsize%5D=100"}})
        if "/hackers/programs?page" in url:
            return Resp(200, {"data": [program(3, "secret", state="soft_launched")], "links": {}})
        if url.endswith("/structured_scopes"):
            handle = url.split("/programs/")[1].split("/")[0]
            return Resp(200, {"data": self.scopes[handle], "links": {}})
        return Resp(404, {})


def client(session):
    return bb.HackerOneClient("user", "token", session=session, sleep=lambda s: None)


def args(tmp_path, **kw):
    a = dict(out=str(tmp_path / "ontology" / "OntoBugBounty_data.ttl"), max_programs=0, include_private=False,
             bounties=None, append=False, dry_run=False, no_hermit=False)
    a.update(kw)
    return SimpleNamespace(**a)


@pytest.fixture(autouse=True)
def evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(bb, "EVIDENCE", str(tmp_path / "bugbounty.json"))


def test_requires_credentials():
    with pytest.raises(bb.H1Error):
        bb.HackerOneClient("", "", session=FakeH1())


def test_pagination_follows_links_next_and_sends_basic_auth():
    s = FakeH1()
    progs = list(client(s).programs())
    assert [p["attributes"]["handle"] for p in progs] == ["acme", "beta", "secret"]
    assert s.calls[0]["params"] == {"page[size]": 100} and s.calls[0]["auth"] == ("user", "token")
    assert s.calls[1]["params"] is None and "page%5Bnumber%5D=2" in s.calls[1]["url"]


def test_429_is_retried_and_401_is_reported():
    s = FakeH1(first=[Resp(429, headers={"Retry-After": "1"})])
    assert len(list(client(s).programs())) == 3
    with pytest.raises(bb.H1Error, match="credenciais"):
        list(client(FakeH1(first=[Resp(401)])).programs())


def test_ingest_public_programs_with_scope_and_validates(tmp_path):
    code = bb.cmd_hackerone(args(tmp_path), client=client(FakeH1()))
    assert code == 0
    g = Graph().parse(str(tmp_path / "ontology" / "OntoBugBounty_data.ttl"), format="turtle")
    P = OC.Program_H1_1
    assert (P, bb.RDF.type, OC.BugBountyProgram) in g and str(g.value(P, OC.programHandle)) == "acme"
    assert g.value(P, OC.hostedOn) == OC.Platform_HackerOne and str(g.value(P, OC.bountyCurrency)) == "USD"
    scopes = {str(g.value(s, OC.scopeIdentifier)) for s in g.objects(P, OC.hasScope)}
    assert scopes == {"app.acme.example", "*.acme.example"}
    assert (OC.Program_H1_2, None, None) not in g                  # sem escopo: recusado
    assert (OC.Program_H1_3, None, None) not in g                  # privado: omitido
    ev = json.load(open(bb.EVIDENCE, encoding="utf-8"))["hackerone"]
    reasons = {r["program"]: r["reason"] for r in ev["rejected"]}
    assert "sem escopo" in reasons["beta"] and "nao publico" in reasons["secret"]
    assert ev["gate"]["conforms"] and ev["gate"]["hermit"]["consistent"]
    assert "politica" not in open(str(tmp_path / "ontology" / "OntoBugBounty_data.ttl"), encoding="utf-8").read()


def test_private_programs_only_with_flag(tmp_path):
    assert bb.cmd_hackerone(args(tmp_path, include_private=True), client=client(FakeH1())) == 0
    g = Graph().parse(str(tmp_path / "ontology" / "OntoBugBounty_data.ttl"), format="turtle")
    assert (OC.Program_H1_3, bb.RDF.type, OC.BugBountyProgram) in g


def test_bounty_table_and_shacl_blocks_invalid_write(tmp_path):
    ok = tmp_path / "ok.json"
    ok.write_text(json.dumps({"acme": {"min": 100, "max": 20000, "source": "https://hackerone.com/acme (politica)"}}))
    assert bb.cmd_hackerone(args(tmp_path, bounties=str(ok)), client=client(FakeH1())) == 0
    g = Graph().parse(str(tmp_path / "ontology" / "OntoBugBounty_data.ttl"), format="turtle")
    assert float(g.value(OC.Program_H1_1, OC.hasMaxBounty)) == 20000.0
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"acme": {"min": 5000, "max": 100, "source": "erro de digitacao"}}))
    out = tmp_path / "blocked" / "data.ttl"
    assert bb.cmd_hackerone(args(tmp_path, bounties=str(bad), out=str(out)), client=client(FakeH1())) == 1
    assert not out.exists()                                         # SHACL falhou: nada gravado
    ev = json.load(open(bb.EVIDENCE, encoding="utf-8"))["hackerone"]
    assert any("maxima" in v["message"] for v in ev["gate"]["violations"])


def test_scopes_beyond_cap_continue_with_id_filter():
    class Many(FakeH1):
        def get(self, url, params=None, **kw):
            self.calls.append({"url": url, "params": params})
            gt = int((params or {}).get("filter[id__gt]") or 0)
            ids = [i for i in range(gt + 1, gt + 4) if i <= 5]
            return Resp(200, {"data": [scope(i, "h%d.example" % i) for i in ids], "links": {}})
    s = Many()
    got = list(client(s).structured_scopes("acme", cap=3))
    assert [x["id"] for x in got] == ["1", "2", "3", "4", "5"]
    assert s.calls[1]["params"]["filter[id__gt]"] == 3
