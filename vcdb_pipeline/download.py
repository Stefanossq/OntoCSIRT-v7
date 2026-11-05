# -*- coding: utf-8 -*-
"""Downloader versionado do VCDB: um ficheiro de um commit fixado, verificado por hash git e SHA-256.

O ficheiro fica em cache/vcdb/<commit>/<nome> com um manifest.json ao lado. Um ficheiro ja presente e
reverificado e nunca descarregado de novo. Um hash diferente do esperado e um erro: nada e substituido.
"""
import datetime
import hashlib
import json
import os

import requests

from . import rules

UA = {"User-Agent": "OntoCSIRT-vcdb-pipeline/1.0 (research prototype)"}
RAW = "https://raw.githubusercontent.com/{repo}/{commit}/{path}"


class IntegrityError(RuntimeError):
    pass


def git_blob_sha1(data):
    """Hash de objeto 'blob' do git (o mesmo que `git hash-object`), comparavel com a API do GitHub."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def verify(data, expected_blob=rules.VCDB_JOINED_GIT_BLOB, expected_sha256=rules.VCDB_JOINED_SHA256):
    got_blob, got_sha = git_blob_sha1(data), sha256(data)
    if got_blob != expected_blob or got_sha != expected_sha256:
        raise IntegrityError("hash diferente do fixado: blob %s (esperado %s), sha256 %s (esperado %s)"
                             % (got_blob, expected_blob, got_sha, expected_sha256))
    return {"git_blob_sha1": got_blob, "sha256": got_sha, "bytes": len(data)}


def local_path(cache_dir, commit=rules.VCDB_COMMIT, path=rules.VCDB_JOINED_PATH):
    return os.path.join(cache_dir, commit, os.path.basename(path))


def fetch(cache_dir, offline=False, session=None, repo=rules.VCDB_REPO, commit=rules.VCDB_COMMIT,
          path=rules.VCDB_JOINED_PATH, expected_blob=rules.VCDB_JOINED_GIT_BLOB,
          expected_sha256=rules.VCDB_JOINED_SHA256, timeout=60):
    """Devolve (caminho_local, manifest). Descarrega so se o ficheiro ainda nao existir."""
    dst = local_path(cache_dir, commit, path)
    man_path = os.path.join(os.path.dirname(dst), "manifest.json")
    if os.path.exists(dst):
        with open(dst, "rb") as fh:
            info = verify(fh.read(), expected_blob, expected_sha256)
        manifest = json.load(open(man_path, encoding="utf-8")) if os.path.exists(man_path) else {}
        manifest.update({"repo": repo, "commit": commit, "path": path, **info})
        return dst, manifest
    if offline:
        raise FileNotFoundError("modo offline e %s nao existe; corra sem --offline uma vez" % dst)
    url = RAW.format(repo=repo, commit=commit, path=path)
    resp = (session or requests).get(url, headers=UA, timeout=timeout)
    resp.raise_for_status()
    data = resp.content
    info = verify(data, expected_blob, expected_sha256)          # antes de escrever: nada parcial em disco
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    tmp = dst + ".part"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, dst)
    manifest = {"repo": repo, "commit": commit, "path": path, "url": url, "license": rules.VCDB_LICENSE,
                "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                **info}
    with open(man_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
        fh.write("\n")
    return dst, manifest
