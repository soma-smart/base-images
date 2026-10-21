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
import decision_publication  # noqa: E402
from decision_publication import LABEL_SOURCES, DecisionError, decider, ecrire  # noqa: E402

REF = "registry-dev.soma-smart.cloud/base/python-slim:3.14"
CAND = "base-python-slim-candidat:3.14"
BASE = "python:3.14-slim"
D = "sha256:" + "d" * 64
PUB = f"registry-dev.soma-smart.cloud/base/python-slim@{D}"
INV = "libc6\t2.41-12\tamd64\nca-certificates\t20250419\tall\nlibgomp1\t14.2\tamd64\n"
INV_CA = INV.replace("20250419\t", "20250419+deb13u1\t")
BASE_C = ["sha256:l1", "sha256:l2"]
ARBRE = "a1" * 20


def faux(inv_cand=INV, inv_pub=INV, pub_layers=None, label=ARBRE, digest=D, crane_rc=0, crane_err="", base_layers=None,
         rc=None, leve=None, labels_brut=None, cand_base=None):
    """Rejoue crane/docker. Le CANDIDAT est toujours « frais » (couches = base courante + les siennes, label = ARBRE) : c'est
    ce que produit `docker build --pull`. Lire couches ou label du candidat au lieu du publié ne verrait donc JAMAIS un
    changement — le faux doit pouvoir les distinguer. `rc` : {commande: code} pour faire échouer docker pull/run/inspect."""
    pub_layers = BASE_C + ["sha256:p1"] if pub_layers is None else pub_layers
    base_layers = BASE_C if base_layers is None else base_layers
    rc = rc or {}
    appels = []

    def run(argv, **kw):
        appels.append(list(argv))
        if leve:
            raise leve
        out, code, err = "", 0, ""
        cle = " ".join(argv[:2])
        if argv[0] == "crane":
            out, code, err = (digest + "\n" if not crane_rc else ""), crane_rc, crane_err
        elif argv[:2] == ["docker", "run"]:
            out = inv_cand if CAND in argv else inv_pub
        elif argv[:2] == ["docker", "image"]:
            image, gab = argv[-1], argv[-2]
            if "Layers" in gab:
                out = json.dumps((base_layers if cand_base is None else cand_base) + ["sha256:c1"] if image == CAND else base_layers if image == BASE else pub_layers)
            elif image == CAND:
                out = json.dumps({LABEL_SOURCES: ARBRE})
            elif labels_brut is not None:
                out = labels_brut
            else:
                out = json.dumps({LABEL_SOURCES: label} if label is not None else {})
        if rc.get(cle):
            out, code, err = "", rc[cle], "boom"
        return subprocess.CompletedProcess(argv, code, stdout=out, stderr=err)

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
    attend_publie("label illisible", "illisible", label="pas un arbre")
    attend_publie("label injecté", "illisible", label="x\npublier=false")
    attend_publie("sources différentes", "sources", label="b" * 40)
    attend_echec("auth refusée", "denied", crane_rc=1, crane_err="UNAUTHORIZED: denied")
    attend_echec("réseau", "timeout", crane_rc=1, crane_err="dial tcp: timeout")
    attend_echec("inventaire candidat vide", "libc6", inv_cand="")
    attend_echec("inventaire publié vide", "libc6", inv_pub="")
    attend_echec("inventaire sans libc6", "libc6", inv_cand="ca-certificates\t1\tall\n", inv_pub="ca-certificates\t1\tall\n")
    attend_echec("digest illisible", "illisible", digest="")
    attend_echec("base sans couche", "aucune couche", base_layers=[], label=ARBRE)
    attend_echec("base lue ≠ base du candidat (tag périmé ou déplacé)", "pas construit sur", base_layers=["sha256:l1", "sha256:NEUF"], cand_base=BASE_C)
    # `docker inspect` rend le JSON `null` pour une image SANS label : c'est le cas de l'image publiée avant ce changement.
    attend_publie("labels null (image publiée avant le label)", "absent", labels_brut="null")
    attend_publie("libc6-dev ne vaut pas libc6 pour le tri", "inventaire", inv_cand=INV, inv_pub=INV.replace("14.2", "14.3"))
    attend_publie("architecture seule différente", "inventaire", inv_pub=INV.replace("libgomp1\t14.2\tamd64", "libgomp1\t14.2\tarm64"))
    attend_publie("NAME_UNKNOWN", "aucune image", crane_rc=1, crane_err="NAME_UNKNOWN: repository name not known")
    for cmd in ("docker pull", "docker run", "docker image"):
        attend_echec(f"{cmd} en échec", "boom", rc={cmd: 1})
    attend_echec("délai dépassé", "delai", leve=subprocess.TimeoutExpired(["x"], 1))
    attend_echec("crane introuvable", "introuvable", leve=FileNotFoundError())
    for mauvais in ("sha256:abc", "sha256:" + "d" * 63, "sha256:" + "d" * 64 + "x", "sha256:" + "G" * 64):
        attend_echec(f"digest {mauvais[:14]}…", "illisible", digest=mauvais)
    # un inventaire où seul un paquet `libc6-dev` existe n'est PAS un inventaire lisible
    attend_echec("libc6-dev sans libc6", "libc6", inv_cand="libc6-dev\t1\tamd64\n", inv_pub="libc6-dev\t1\tamd64\n")
    # même paquets, autre ordre de sortie : pas de faux « publier »
    (publier, _, _), _ = verdict(inv_cand="\n".join(reversed(INV.strip().splitlines())) + "\n")
    assert not publier, "l'ordre de sortie de dpkg-query ne doit pas déclencher de publication"
    # lectures de couches et de label : toujours sur le PUBLIÉ, jamais sur le candidat
    _, appels = verdict()
    inspects = [a for a in appels if a[:2] == ["docker", "image"]]
    assert inspects and all(a[-1] in (PUB, BASE, CAND) for a in inspects), f"inspect sur le candidat : {inspects}"
    # sortie vers le workflow
    import tempfile
    with tempfile.TemporaryDirectory() as t:
        f = Path(t) / "out"
        ecrire(str(f), False, "r", D)
        ecrire(str(f), True, "r2", None)
        g = Path(t) / "inj"
        ecrire(str(g), True, "a\npublier=false\r\ndigest=sha256:x", None)
        assert g.read_text().count("\n") == 3 and g.read_text().startswith("publier=true\nraison=a publier=false"), g.read_text()
        assert f.read_text() == f"publier=false\nraison=r\ndigest={D}\npublier=true\nraison=r2\ndigest=\n", f.read_text()
    for args, attendu in (([], "Usage"), (["a", "b", "c", "d"], "ERREUR")):
        r = subprocess.run([sys.executable, "-I", str(Path(decision_publication.__file__)), *args], capture_output=True, text=True)
        assert r.returncode != 0 and attendu in r.stderr, (args, r.returncode, r.stderr)
    print("test_decision_publication : OK")


if __name__ == "__main__":
    jouer()
