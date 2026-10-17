#!/usr/bin/env python3
"""Exerce `copie_ghcr.py` surtout dans ses modes d'ECHEC.

⚠️ UNE COPIE QUI PUBLIE SANS PROUVER L'EGALITE DES DIGESTS, OU SANS PROUVER QUE LE PACKAGE EST
LISIBLE EN ANONYME, FAIT ECHOUER LES PULLS DU POD DE BUILD (401) ALORS QUE LE JOB EST VERT. Les cas
ci-dessous sont des chemins par lesquels la copie sortirait en succes sans avoir rien prouve
(digest vide des deux cotes, package prive, digest voisin) ou des echecs qui doivent rester
lisibles (crane introuvable, delai depasse, source sans tag).
"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from copie_ghcr import CopieError, copier_et_verifier  # noqa: E402

SRC = "registry-dev.soma-smart.cloud/base/python-slim:3.14"
DST = "ghcr.io/soma-smart/base/python-slim:3.14"
A = "sha256:" + "a" * 64
B = "sha256:" + "b" * 64


def faux_crane(src=A, dst=A, anon=A, rc_src=0, rc_copy=0, rc_dst=0, rc_anon=0, leve=None):
    """Rejoue `crane` : renvoie (run, appels). Un appel avec `env` = relecture ANONYME (DOCKER_CONFIG vide)."""
    appels = []

    def run(argv, **kw):
        appels.append((list(argv), kw))
        if leve:
            raise leve
        if argv[1] == "copy":
            return subprocess.CompletedProcess(argv, rc_copy, stdout="", stderr="boom" if rc_copy else "")
        assert argv[1] == "digest", argv
        if kw.get("env"):
            sortie, rc = anon, rc_anon
        elif argv[2] == SRC or ":5000/" in argv[2]:
            sortie, rc = src, rc_src
        else:
            sortie, rc = dst, rc_dst
        return subprocess.CompletedProcess(argv, rc, stdout=sortie + "\n", stderr="denied" if rc else "")

    return run, appels


def copies(appels):
    return [a for a, _ in appels if a[1] == "copy"]


def attend_echec(nom, run_appels, fragments, src=SRC, copie_interdite=False):
    run, appels = run_appels
    try:
        copier_et_verifier(src, DST, run=run)
    except CopieError as e:
        manque = [f for f in fragments if f not in str(e)]
        assert not manque, f"{nom} : message sans {manque} : {e}"
        assert not (copie_interdite and copies(appels)), f"{nom} : une copie a eu lieu malgre l'echec"
        return
    raise AssertionError(f"{nom} : aucune CopieError levee")


def jouer():
    n = 0
    run, appels = faux_crane()
    assert copier_et_verifier(SRC, DST, run=run) == A, "nominal"
    c = copies(appels)
    assert len(c) == 1 and c[0][2] == f"registry-dev.soma-smart.cloud/base/python-slim@{A}" and c[0][3] == DST, \
        f"la copie doit partir du DIGEST, pas du tag : {c}"
    assert any(kw.get("env") for _, kw in appels), "aucune relecture anonyme"
    n += 2
    run, appels = faux_crane()
    copier_et_verifier("host:5000/x:tag", DST, run=run)
    assert copies(appels)[0][2] == f"host:5000/x@{A}", "un port d'hote ne doit pas etre pris pour un tag"
    n += 1
    attend_echec("digest_different", faux_crane(dst=B), [A, B])
    attend_echec("digest_voisin", faux_crane(dst=A + "x"), [A])
    attend_echec("copie_en_echec", faux_crane(rc_copy=1), ["boom"])
    attend_echec("source_vide_des_deux_cotes", faux_crane(src="", dst=""), ["illisible"], copie_interdite=True)
    attend_echec("source_pas_un_digest", faux_crane(src="md5:abc", dst="md5:abc"), ["illisible"], copie_interdite=True)
    attend_echec("source_digest_court", faux_crane(src="sha256:aaa", dst="sha256:aaa"), ["illisible"], copie_interdite=True)
    attend_echec("crane_digest_source_en_echec", faux_crane(rc_src=1), ["denied"], copie_interdite=True)
    attend_echec("crane_digest_destination_en_echec", faux_crane(rc_dst=1), ["denied"])
    attend_echec("package_prive", faux_crane(rc_anon=1), ["public", "anonyme"])
    attend_echec("anonyme_voit_un_autre_digest", faux_crane(anon=B), [A, B])
    attend_echec("source_sans_tag_avec_port", faux_crane(), ["tag"], src="host:5000/x", copie_interdite=True)
    attend_echec("source_deja_un_digest", faux_crane(), ["tag"], src=f"host/x@{A}", copie_interdite=True)
    attend_echec("crane_introuvable", faux_crane(leve=FileNotFoundError("crane")), ["crane"])
    attend_echec("delai_depasse", faux_crane(leve=subprocess.TimeoutExpired("crane", 1)), ["delai"])
    n += 13
    r = subprocess.run([sys.executable, str(Path(__file__).with_name("copie_ghcr.py")), SRC, DST],
                       capture_output=True, text=True, env={"PATH": "/nonexistent"})
    assert r.returncode != 0 and "ERREUR:" in r.stderr, (r.returncode, r.stderr)
    n += 1
    print(f"ok : {n} verifications")


if __name__ == "__main__":
    jouer()
