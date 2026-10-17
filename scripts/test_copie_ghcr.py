#!/usr/bin/env python3
"""Exerce `copie_ghcr.py` dans ses modes d'ECHEC, pas sur son chemin heureux.

⚠️ UNE COPIE QUI PUBLIE SANS PROUVER L'EGALITE DES DIGESTS FAIT RESOUDRE LES EPINGLES DES
CONSOMMATEURS CONTRE UN OBJET QUI N'EXISTE PAS SUR GHCR. Chaque cas ci-dessous est un chemin
par lequel la copie rendrait VERT sans avoir rien prouve.
"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from copie_ghcr import CopieError, copier_et_verifier  # noqa: E402

SRC = "registry-dev.soma-smart.cloud/base/python-slim:3.14"
DST = "ghcr.io/soma-smart/base/python-slim:3.14"


def faux_crane(digest_src="sha256:aaa", digest_dst="sha256:aaa", rc_copy=0):
    """Rejoue `crane` : renvoie (run, appels). `appels` garde chaque argv pour les assertions."""
    appels = []

    def run(argv, **_kw):
        appels.append(list(argv))
        verbe = argv[1]
        if verbe == "digest":
            d = digest_src if argv[2] == SRC else digest_dst
            return subprocess.CompletedProcess(argv, 0, stdout=d + "\n", stderr="")
        if verbe == "copy":
            return subprocess.CompletedProcess(argv, rc_copy, stdout="", stderr="boom" if rc_copy else "")
        raise AssertionError(f"commande inattendue : {argv}")

    return run, appels


def attend_echec(nom, run, fragments):
    try:
        copier_et_verifier(SRC, DST, run=run)
    except CopieError as e:
        manque = [f for f in fragments if f not in str(e)]
        assert not manque, f"{nom} : message sans {manque} : {e}"
        return
    raise AssertionError(f"{nom} : aucune CopieError levee")


def jouer():
    run, appels = faux_crane()
    assert copier_et_verifier(SRC, DST, run=run) == "sha256:aaa", "nominal"
    copie = [a for a in appels if a[1] == "copy"]
    assert len(copie) == 1 and copie[0][2] == f"{SRC.rsplit(':', 1)[0]}@sha256:aaa", \
        f"la copie doit partir du DIGEST, pas du tag : {copie}"
    assert copie[0][3] == DST, copie
    attend_echec("digest_different", faux_crane(digest_dst="sha256:bbb")[0], ["sha256:aaa", "sha256:bbb"])
    attend_echec("copie_en_echec", faux_crane(rc_copy=1)[0], ["boom"])
    attend_echec("digest_source_vide", faux_crane(digest_src="")[0], ["digest"])
    print("ok : 5 cas")


if __name__ == "__main__":
    jouer()
