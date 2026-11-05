# -*- coding: utf-8 -*-
"""Cliente NVD CVE API 2.0 com cache por CVE e envelope de proveniencia (contrato 4.3).

Um ficheiro por CVE em <cache>/<CVE>.json:
  {request_url, retrieved_at, response_timestamp, nvd_api_version, nvd_api_format, sha256_of_cve_object,
   notice, cve: {...}}
A cache e um instantaneo congelado: nao expira. Para atualizar, refresh=True. Em modo offline so a cache e
lida. Limites [S10]: 5 pedidos / 30 s sem chave, 50 com chave; pausa de 6 s entre pedidos; cveIds aceita
ate 100 IDs por pedido [S9].
"""
import datetime
import hashlib
import json
import os
import time

import requests

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
BATCH = 100                                   # [S9] cveIds: "limited to a maximum of 100 CVE IDs"
SLEEP_BETWEEN = 6.0                           # [S10] "sleep their scripts for six seconds between requests"
RETRY_STATUS = (403, 429, 503)
NOTICE = "This product uses data from the NVD API but is not endorsed or certified by the NVD."   # [S10]
UA = {"User-Agent": "OntoCSIRT-vcdb-pipeline/1.0 (research prototype)"}


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def object_sha256(obj):
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


class NVDCache:
    def __init__(self, directory):
        self.dir = directory

    def path(self, cve_id):
        return os.path.join(self.dir, cve_id + ".json")

    def get(self, cve_id):
        p = self.path(cve_id)
        if not os.path.exists(p):
            return None
        env = json.load(open(p, encoding="utf-8"))
        if env.get("sha256_of_cve_object") != object_sha256(env.get("cve")):
            raise ValueError("envelope NVD adulterado ou corrompido: %s" % p)
        return env

    def put(self, env):
        os.makedirs(self.dir, exist_ok=True)
        p = self.path(env["cve"]["id"])
        tmp = p + ".part"
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(env, fh, indent=1, sort_keys=True, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, p)


def envelope(cve_obj, request_url, response):
    return {"request_url": request_url,
            "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "response_timestamp": response.get("timestamp"),
            "nvd_api_version": response.get("version"),
            "nvd_api_format": response.get("format"),
            "sha256_of_cve_object": object_sha256(cve_obj),
            "notice": NOTICE,
            "cve": cve_obj}


def _validator(schema_path):
    if not schema_path or not os.path.exists(schema_path):
        return None
    import jsonschema
    return jsonschema.Draft7Validator(json.load(open(schema_path, encoding="utf-8")))


def fetch(cve_ids, cache, offline=False, refresh=False, api_key=None, session=None, sleep=time.sleep,
          schema_path=None, max_retries=4, timeout=(5, 60)):
    """Devolve (envelopes {cve: env}, info). CVEs que o NVD nao devolve ficam em info['missing']."""
    wanted = sorted(set(cve_ids))
    found, info = {}, {"requests": 0, "from_cache": 0, "fetched": 0, "missing": [], "schema_errors": []}
    todo = []
    for c in wanted:
        env = None if refresh else cache.get(c)
        if env is not None:
            found[c] = env
            info["from_cache"] += 1
        else:
            todo.append(c)
    if offline:
        info["missing"] = todo
        return found, info
    val = _validator(schema_path)
    http = session or requests.Session()
    headers = dict(UA, **({"apiKey": api_key} if api_key else {}))
    for i in range(0, len(todo), BATCH):
        chunk = todo[i:i + BATCH]
        if info["requests"]:
            sleep(SLEEP_BETWEEN)
        url = "%s?cveIds=%s" % (API, ",".join(chunk))
        for attempt in range(max_retries + 1):
            resp = http.get(url, headers=headers, timeout=timeout)
            info["requests"] += 1
            if resp.status_code in RETRY_STATUS and attempt < max_retries:
                sleep(SLEEP_BETWEEN * (attempt + 2))
                continue
            resp.raise_for_status()
            break
        data = resp.json()
        if val is not None:
            info["schema_errors"] += ["%s: %s" % ("/".join(map(str, e.path)), e.message[:120])
                                      for e in list(val.iter_errors(data))[:5]]
        for item in data.get("vulnerabilities") or []:
            cve_obj = item["cve"]
            if cve_obj.get("id") in chunk:
                env = envelope(cve_obj, url, data)
                cache.put(env)
                found[cve_obj["id"]] = env
                info["fetched"] += 1
    info["missing"] = sorted(c for c in wanted if c not in found)
    return found, info
