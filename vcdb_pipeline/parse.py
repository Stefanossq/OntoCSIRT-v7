# -*- coding: utf-8 -*-
"""Leitura do joined do VCDB (zip com um unico JSON cuja raiz e uma lista de incidentes) [S4], [S7]."""
import json
import zipfile


class FormatError(ValueError):
    pass


def read_joined(path):
    with zipfile.ZipFile(path) as z:
        names = [n for n in z.namelist() if not n.endswith("/")]
        if len(names) != 1 or not names[0].endswith(".json"):
            raise FormatError("esperado um unico .json no zip, encontrado %s" % names)
        data = json.loads(z.read(names[0]).decode("utf-8"))
    if not isinstance(data, list):
        raise FormatError("a raiz do joined deve ser uma lista (vcdb_to_joined.py) e e %s" % type(data).__name__)
    return names[0], data


def schema_check(records, schema_path):
    """Valida cada registo contra vcdb-merged.json [S2]. Informativo: so entra no relatorio de cobertura."""
    import jsonschema
    schema = json.load(open(schema_path, encoding="utf-8"))
    validator = jsonschema.Draft4Validator(schema)
    failures = {}
    for i, rec in enumerate(records):
        errs = sorted(validator.iter_errors(rec), key=lambda e: list(e.path))
        if errs:
            failures[(rec.get("plus") or {}).get("master_id") or "#%d" % i] = [
                "%s: %s" % ("/".join(map(str, e.path)) or "<raiz>", e.message[:160]) for e in errs[:3]]
    return failures
