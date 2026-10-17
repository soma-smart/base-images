#!/usr/bin/env python3
"""Copie une base de Harbor vers ghcr PAR DIGEST et refuse si le digest ghcr diffère.

⚠️ POURQUOI PAR DIGEST ET PAS PAR TAG. Le tag Harbor est mouvant : entre « lire le digest »
et « copier », un rebuild peut le déplacer, et l'on publierait sur ghcr un objet que l'on n'a
pas vérifié. On fige le digest d'abord, on copie CE digest, puis on relit la destination.

⚠️ POURQUOI L'ÉGALITÉ EST ASSERTÉE. Les consommateurs épinglent `repo:tag@sha256:…`. Une copie
qui recompresse ou convertit le format produit un AUTRE digest : l'épingle ne résoudrait plus
sur ghcr, sans aucune erreur de copie.

⚠️ POURQUOI UNE RELECTURE ANONYME. La relecture authentifiée réussit sur un package PRIVÉ : le
job resterait vert pendant que le pod de build (anonyme) reçoit un 401. Un package créé par
`GITHUB_TOKEN` est privé tant que quelqu'un ne l'a pas basculé à la main, et peut le redevenir :
la relecture tourne donc à chaque exécution, avec un `DOCKER_CONFIG` vide.

Usage : copie_ghcr.py <source repo:tag> <destination repo:tag> — code 0 = digests égaux et
destination lisible sans identifiants.
"""
import os
import re
import subprocess
import sys
import tempfile

DELAI_S = 300
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class CopieError(RuntimeError):
    pass


def _crane(run, *args, env=None):
    try:
        r = run(["crane", *args], capture_output=True, text=True, timeout=DELAI_S, env=env)
    except FileNotFoundError:
        raise CopieError("crane est introuvable dans le PATH") from None
    except subprocess.TimeoutExpired:
        raise CopieError(f"delai de {DELAI_S}s depasse : crane {' '.join(args)}") from None
    if r.returncode != 0:
        raise CopieError(f"crane {' '.join(args)} a échoué (code {r.returncode}) : {(r.stderr or '').strip()}")
    return (r.stdout or "").strip()


def _depot(src):
    """`repo` d'une référence `repo:tag`. Refuse `repo@sha256:…` et `host:port/repo` (aucun tag : le `:` est celui du port)."""
    nom, sep, tag = src.rpartition(":")
    if "@" in src or not sep or "/" in tag:
        raise CopieError(f"la source doit être `repo:tag` (un tag, pas un digest ni un simple port) : {src!r}")
    return nom


def copier_et_verifier(src, dst, run=subprocess.run):
    depot = _depot(src)
    digest = _crane(run, "digest", src)
    if not DIGEST.match(digest):
        raise CopieError(f"digest source illisible pour {src} : {digest!r}")
    _crane(run, "copy", f"{depot}@{digest}", dst)
    obtenu = _crane(run, "digest", dst)
    if obtenu != digest:
        raise CopieError(f"digest différent après copie : source {digest}, destination {obtenu} ({dst})")
    with tempfile.TemporaryDirectory() as vide:
        try:
            # Environnement bâti DE ZÉRO, pas dérivé de `os.environ` : le job exporte GITHUB_TOKEN (et gh/docker peuvent
            # lire d'autres variables d'auth) ; une relecture « anonyme » qui en hérite lirait un package privé.
            anonyme = _crane(run, "digest", dst, env={"PATH": os.environ.get("PATH", ""), "HOME": vide, "DOCKER_CONFIG": vide})
        except CopieError as e:
            raise CopieError(f"{dst} illisible en anonyme : le package ghcr n'est pas public (Package settings > "
                             f"Change visibility) — les pulls anonymes du pod de build feront 401. {e}") from None
    if anonyme != digest:
        raise CopieError(f"lecture anonyme : digest {anonyme} ≠ {digest} ({dst})")
    return digest


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    try:
        print(copier_et_verifier(sys.argv[1], sys.argv[2]))
    except CopieError as e:
        sys.exit(f"ERREUR: {e}")
