#!/usr/bin/env python3
"""Exerce `decision_publication.py`, surtout dans ses modes d'ÉCHEC.

⚠️ UNE DÉCISION QUI SAUTE À TORT NE FAIT AUCUN BRUIT : le socle cesse d'être republié, le job reste vert, et un
correctif Debian n'arrive jamais. Chaque cas « publie » ci-dessous est un chemin par lequel un changement réel
passerait pour « inchangé » ; chaque cas « échoue » est une lecture qui ne doit jamais valoir « inchangé ».
"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from decision_publication import LABEL_SOURCES, DecisionError, decider  # noqa: E402

REF = "registry-dev.soma-smart.cloud/base/python-slim:3.14"
CAND = "base-python-slim-candidat:3.14"
BASE = "python:3.14-slim"
D = "sha256:" + "d" * 64
PUB = f"registry-dev.soma-smart.cloud/base/python-slim@{D}"
INV = "libc6\t2.41-12\tamd64\nca-certificates\t20250419\tall\nlibgomp1\t14.2\tamd64\n"
INV_CA = INV.replace("20250419\t", "20250419+deb13u1\t")
BASE_C = ["sha256:l1", "sha256:l2"]
ARBRE = "t" * 40


def faux(inv_cand=INV, inv_pub=INV, pub_layers=None, label=ARBRE, digest=D, crane_rc=0, crane_err="", base_layers=None):
    pub_layers = BASE_C + ["sha256:p1"] if pub_layers is None else pub_layers
    base_layers = BASE_C if base_layers is None else base_layers
    appels = []

    def run(argv, **kw):
        appels.append(list(argv))
        out, rc, err = "", 0, ""
        if argv[0] == "crane":
            out, rc, err = (digest + "\n" if not crane_rc else ""), crane_rc, crane_err
        elif argv[:2] == ["docker", "run"]:
            out = inv_cand if CAND in argv else inv_pub
        elif argv[:2] == ["docker", "image"]:
            image, gab = argv[-1], argv[-2]
            if "Layers" in gab:
                out = json.dumps(base_layers if image == BASE else pub_layers)
            else:
                out = json.dumps({LABEL_SOURCES: label} if label is not None else {})
        return subprocess.CompletedProcess(argv, rc, stdout=out, stderr=err)

    return run, appels


def verdict(**kw):
    run, appels = faux(**kw)
    return decider(run, CAND, REF, BASE, ARBRE), appels


def attend_publie(nom, fragment, **kw):
    (publier, raison, _), _ = verdict(**kw)
    assert publier and fragment in raison, f"{nom} : {publier} / {raison}"


def attend_echec(nom, fragment, **kw):
    try:
        verdict(**kw)
    except DecisionError as e:
        assert fragment in str(e), f"{nom} : message sans {fragment!r} : {e}"
        return
    raise AssertionError(f"{nom} : aucune DecisionError (un cas illisible a été jugé « inchangé » ou « publié »)")


def jouer():
    (publier, raison, digest), appels = verdict()
    assert not publier and digest == D, f"deux builds sans changement de paquet doivent SAUTER : {raison}"
    assert any(a[:2] == ["docker", "pull"] and a[-1] == PUB for a in appels), "l'image publiée doit être lue PAR DIGEST"
    assert all(REF not in a for a in appels if a[:2] == ["docker", "run"]), "aucune lecture d'inventaire par le TAG mouvant"
    attend_publie("ca-certificates +deb13u1", "inventaire", inv_cand=INV_CA)
    attend_publie("paquet retiré", "inventaire", inv_cand=INV.replace("libgomp1\t14.2\tamd64\n", ""))
    attend_publie("tag absent", "aucune image", crane_rc=1, crane_err="MANIFEST_UNKNOWN: manifest unknown")
    attend_publie("base changée (couche remplacée)", "base", base_layers=["sha256:l1", "sha256:NEUF"])
    attend_publie("base changée (couche ajoutée)", "base", base_layers=BASE_C + ["sha256:l3"])
    attend_publie("label absent", "absent", label=None)
    attend_publie("sources différentes", "sources", label="u" * 40)
    attend_echec("auth refusée", "denied", crane_rc=1, crane_err="UNAUTHORIZED: denied")
    attend_echec("réseau", "timeout", crane_rc=1, crane_err="dial tcp: timeout")
    attend_echec("inventaire candidat vide", "libc6", inv_cand="")
    attend_echec("inventaire publié vide", "libc6", inv_pub="")
    attend_echec("inventaire sans libc6", "libc6", inv_cand="ca-certificates\t1\tall\n", inv_pub="ca-certificates\t1\tall\n")
    attend_echec("digest illisible", "illisible", digest="")
    attend_echec("base sans couche", "aucune couche", base_layers=[], label=ARBRE)
    # le même contrôle négatif : si le candidat est lu sous le nom du tag publié, la décision serait faussée — l'invariant
    # est que le candidat porte un nom DISTINCT, vérifié ici par la présence de CAND dans les lectures d'inventaire.
    _, appels = verdict()
    assert sum(CAND in a for a in appels if a[:2] == ["docker", "run"]) == 1
    print("test_decision_publication : OK")


if __name__ == "__main__":
    jouer()
