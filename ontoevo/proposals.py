# -*- coding: utf-8 -*-
"""
proposals.py - ciclo de vida das propostas de evolucao e aplicacao no OWL.

  invalid        a proposta nao compila (erros estruturais) - guardada para auditoria
  failed-gate    compila mas nao passa no portao (SHACL/HermiT/Pellet/regressao)
  pending        passou no portao; aguarda decisao humana
  approved       aprovada por um analista (registo de quem e quando)
  rejected       recusada por um analista (com nota)
  applied        acrescentada a OntoCSIRT_v7_evo.ttl (e retracoes residuais nos dados), verificada
  failed-apply   o portao voltou a falhar no momento de aplicar (a base mudou) ou a verificacao
                 posterior falhou - os ficheiros foram restaurados das copias

Aplicar = recompilar e repassar o portao sobre a base ATUAL; copia de seguranca de cada ficheiro tocado;
acrescentar o bloco Turtle ao modulo de evolucao (com evo:approvedBy/approvedOn); retracoes so nos
ficheiros de dados; versionInfo evo-N -> evo-N+1; verificacao final (SHACL + HermiT + Pellet + questoes de
competencia) sobre os ficheiros gravados; registo em evolution/CHANGELOG.json. Se a verificacao final
falhar, tudo e restaurado.
"""
import datetime
import glob
import json
import os
import re
import shutil

from rdflib import Graph, Literal
from rdflib.namespace import XSD

import validar_ingestao as val

from . import compiler, evogate, kb
from .schemas import OntologyChangeProposal

HERE = kb.HERE
DIR = os.path.join(HERE, "evolution", "proposals")
CHANGELOG = os.path.join(HERE, "evolution", "CHANGELOG.json")


def _rel(path):
    """Caminho relativo a raiz do projeto, com '/' (None fica None)."""
    if not path:
        return path
    try:
        return os.path.relpath(path, HERE).replace(os.sep, "/")
    except ValueError:                      # outra unidade no Windows
        return os.path.basename(path)


class ProposalError(RuntimeError):
    pass


class Store:
    def __init__(self, directory=None, evo_path=None, changelog=None, profile="real", acquired_path=None):
        self.dir = directory or DIR
        self.evo = evo_path or val.EVO
        self.changelog = changelog or CHANGELOG
        self.profile, self.acquired_path = profile, acquired_path

    # ---------------------------------------------------------------- persistencia
    def _path(self, pid):
        return os.path.join(self.dir, pid + ".json")

    def new_id(self):
        day = datetime.date.today().strftime("%Y%m%d")
        os.makedirs(self.dir, exist_ok=True)
        n = len(glob.glob(os.path.join(self.dir, "EVO-%s-*.json" % day)))
        return "EVO-%s-%03d" % (day, n + 1)

    def save(self, rec):
        os.makedirs(self.dir, exist_ok=True)
        with open(self._path(rec["id"]), "w", encoding="utf-8") as f:
            json.dump(rec, f, ensure_ascii=False, indent=1, default=str)
        return rec

    def get(self, pid):
        p = self._path(pid)
        if not os.path.exists(p):
            raise ProposalError("proposta %s inexistente" % pid)
        with open(p, encoding="utf-8") as f:
            return json.load(f)

    def list(self, status=None):
        out = []
        for p in sorted(glob.glob(os.path.join(self.dir, "EVO-*.json"))):
            with open(p, encoding="utf-8") as f:
                r = json.load(f)
            if status is None or r["status"] == status:
                out.append(r)
        return out

    @staticmethod
    def _event(rec, action, by=None, note=None):
        rec.setdefault("history", []).append({"at": datetime.datetime.now().isoformat(timespec="seconds"),
                                              "action": action, "by": by, "note": note})

    # ---------------------------------------------------------------- criar
    def create(self, proposal, proposed_by, signal=None, llm_meta=None, regression=True):
        """Valida o esquema, compila e passa no portao. Devolve o registo gravado."""
        p = proposal if isinstance(proposal, OntologyChangeProposal) else OntologyChangeProposal.model_validate(proposal)
        pid = self.new_id()
        g = kb.load(self.profile, acquired_path=self.acquired_path)
        comp = compiler.compile_proposal(p, g, pid, proposed_by)
        rec = {"id": pid, "created": datetime.datetime.now().isoformat(timespec="seconds"), "proposed_by": proposed_by,
               "signal": signal, "llm": llm_meta, "proposal": p.model_dump(), "compiled": comp.summary(),
               "turtle": comp.turtle() if comp.ok else None}
        if not comp.ok:
            rec["status"], rec["gate"] = "invalid", None
        else:
            gate = evogate.run(comp, self.profile, self.acquired_path, regression=regression)
            rec["gate"] = gate
            rec["status"] = "pending" if gate["passed"] else "failed-gate"
        self._event(rec, "created", proposed_by, rec["status"])
        return self.save(rec)

    # ---------------------------------------------------------------- decidir
    def approve(self, pid, by, note=None):
        rec = self.get(pid)
        if rec["status"] != "pending":
            raise ProposalError("so propostas 'pending' podem ser aprovadas (%s esta '%s')" % (pid, rec["status"]))
        if not by:
            raise ProposalError("aprovacao exige o nome de quem aprova")
        rec["status"], rec["approved_by"] = "approved", by
        rec["approved_on"] = datetime.date.today().isoformat()
        self._event(rec, "approved", by, note)
        return self.save(rec)

    def reject(self, pid, by, note):
        rec = self.get(pid)
        if rec["status"] in ("applied",):
            raise ProposalError("proposta ja aplicada; a evolucao e monotona (use owl:deprecated numa nova proposta)")
        if not by or not note:
            raise ProposalError("recusa exige quem recusa e uma nota")
        rec["status"] = "rejected"
        self._event(rec, "rejected", by, note)
        return self.save(rec)

    # ---------------------------------------------------------------- aplicar
    def apply(self, pid, by=None):
        rec = self.get(pid)
        if rec["status"] != "approved":
            raise ProposalError("so propostas aprovadas podem ser aplicadas (%s esta '%s')" % (pid, rec["status"]))
        p = OntologyChangeProposal.model_validate(rec["proposal"])
        g = kb.load(self.profile, acquired_path=self.acquired_path)
        comp = compiler.compile_proposal(p, g, pid, rec["proposed_by"])
        gate = evogate.run(comp, self.profile, self.acquired_path) if comp.ok else None
        if not comp.ok or not gate["passed"]:
            rec["status"], rec["apply_gate"] = "failed-apply", gate or comp.summary()
            self._event(rec, "apply-blocked", by, "a base mudou desde a aprovacao; recompilacao/portao falhou")
            self.save(rec)
            raise ProposalError("aplicacao bloqueada: portao falhou na base atual")
        for name in comp.new_classes + comp.new_properties:
            iri = compiler.OC[name]
            comp.adds.add((iri, compiler.EVO.approvedBy, Literal(rec["approved_by"])))
            comp.adds.add((iri, compiler.EVO.approvedOn, Literal(rec["approved_on"], datatype=XSD.date)))
        # retracoes so nos ficheiros de DADOS do perfil em uso (nunca no OntoCSIRT_v7.ttl congelado)
        data_files = [f for f in ((kb.REAL,) if self.profile == "real" else ()) + (self.acquired_path or kb.ACQUIRED,)
                      if os.path.exists(f)]
        targets = {}
        for t in comp.retracts:
            hit = [f for f in data_files if t in _graph(f)]
            if not hit:
                raise ProposalError("retracao %s nao encontrada em nenhum ficheiro de dados" % (t,))
            for f in hit:
                targets.setdefault(f, []).append(t)
        backups = {f: kb.backup(f, pid) for f in [self.evo] + list(targets)}
        try:
            self._append_block(rec, comp)
            for f, ts in targets.items():
                dg = _graph(f)
                for t in ts:
                    dg.remove(t)
                kb.bind(dg).serialize(f, format="turtle")
            verify = self._verify()
            if not verify["ok"]:
                raise ProposalError("verificacao apos aplicar falhou: %s" % verify)
        except Exception:
            for f, b in backups.items():
                if b:
                    shutil.copy2(b, f)
            rec["status"] = "failed-apply"
            self._event(rec, "apply-rolled-back", by, "ficheiros restaurados das copias de seguranca")
            self.save(rec)
            raise
        rec["status"], rec["applied_on"] = "applied", datetime.datetime.now().isoformat(timespec="seconds")
        rec["applied"] = {"evo_version": self._version(), "triples_added": len(comp.adds),
                          "retractions": {os.path.basename(f): len(ts) for f, ts in targets.items()},
                          # caminhos relativos a raiz: o registo nao expoe a maquina de quem aplicou
                          "backups": {os.path.basename(f): _rel(b) for f, b in backups.items()}, "verification": verify}
        self._event(rec, "applied", by or rec.get("approved_by"), rec["applied"]["evo_version"])
        self.save(rec)
        self._log(rec, comp)
        return rec

    def _version(self):
        with open(self.evo, encoding="utf-8") as f:
            m = re.search(r'owl:versionInfo "evo-(\d+)"', f.read())
        return "evo-%s" % (m.group(1) if m else "?")

    def _append_block(self, rec, comp):
        with open(self.evo, encoding="utf-8") as f:
            text = f.read()
        m = re.search(r'owl:versionInfo "evo-(\d+)"', text)
        n = int(m.group(1)) + 1 if m else 1
        text = re.sub(r'owl:versionInfo "evo-\d+"', 'owl:versionInfo "evo-%d"' % n, text, count=1)
        p = rec["proposal"]
        header = ("\n# ---------------------------------------------------------------------------\n"
                  "# %s (evo-%d) %s: %s\n#   proposto por %s; aprovado por %s em %s; sinal %s\n"
                  "# ---------------------------------------------------------------------------\n"
                  % (rec["id"], n, p["kind"], ", ".join(comp.new_classes + comp.new_properties) or p.get("class_name"),
                     rec["proposed_by"], rec["approved_by"], rec["approved_on"], p["signal_id"]))
        with open(self.evo, "w", encoding="utf-8") as f:
            f.write(text.rstrip("\n") + "\n" + header + comp.turtle())

    def _verify(self):
        g = kb.load(self.profile, acquired_path=self.acquired_path)
        rep = val.validate(g, use_pellet=True, use_hermit=True)
        cq, _ = evogate.competency(None)
        ok = rep["conforms"] and rep["hermit"]["consistent"] and not rep["hermit"]["unsatisfiable_classes"] \
            and rep["pellet"]["consistent"] and cq["passed"] == cq["total"]
        return {"ok": ok, "shacl_conforms": rep["conforms"], "violations": [v["message"] for v in rep["violations"]][:10],
                "hermit": rep["hermit"], "pellet": rep["pellet"], "competency": "%d/%d" % (cq["passed"], cq["total"])}

    def _log(self, rec, comp):
        log = []
        if os.path.exists(self.changelog):
            with open(self.changelog, encoding="utf-8") as f:
                log = json.load(f)
        log.append({"id": rec["id"], "version": rec["applied"]["evo_version"], "kind": rec["proposal"]["kind"],
                    "new_classes": comp.new_classes, "new_properties": comp.new_properties, "members": comp.members,
                    "retractions": rec["applied"]["retractions"], "proposed_by": rec["proposed_by"],
                    "approved_by": rec["approved_by"], "applied_on": rec["applied_on"],
                    "signal": rec["proposal"]["signal_id"]})
        os.makedirs(os.path.dirname(self.changelog), exist_ok=True)
        with open(self.changelog, "w", encoding="utf-8") as f:
            json.dump(log, f, ensure_ascii=False, indent=1)


def _graph(path):
    g = Graph()
    g.parse(path, format="turtle")
    return g
