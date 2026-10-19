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

⚠️ SOURCE ÉPINGLÉE. Une source `repo[:tag]@sha256:…` fixe le digest À L'AVANCE : c'est celui qu'un gate a déjà scanné, et le
résoudre une seconde fois par le tag laisserait un rebuild amont le déplacer entre le scan et la copie (on publierait un objet
jamais scanné). Le digest donné EST alors celui copié, et l'égalité est assertée sur la destination.

Usage : copie_ghcr.py <source repo:tag | repo[:tag]@sha256:…> <destination repo:tag> — code 0 = digests égaux et
destination lisible sans identifiants.
"""
import os
import re
import subprocess
import sys
import tempfile

DELAI_S = 300
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}\Z")
VARIABLES_RESEAU = frozenset({"SSL_CERT_FILE", "SSL_CERT_DIR", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
                              "https_proxy", "http_proxy", "no_proxy"})


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
    """(`repo`, digest ou None) d'une source `repo:tag` (digest None : à résoudre) ou `repo[:tag]@sha256:…` (digest épinglé).
    Refuse une source sans tag ni digest, dont `host:port/repo` (le `:` est celui du port)."""
    if "@" in src:
        nom, _, digest = src.partition("@")
        if not DIGEST.match(digest):
            raise CopieError(f"digest épinglé illisible dans la source : {src!r}")
        reste, sep, tag = nom.rpartition(":")
        return (reste if sep and "/" not in tag else nom), digest
    nom, sep, tag = src.rpartition(":")
    if not sep or "/" in tag:
        raise CopieError(f"la source doit être `repo:tag` ou `repo@sha256:…` (pas un simple port) : {src!r}")
    return nom, None


def copier_et_verifier(src, dst, run=subprocess.run):
    depot, digest = _depot(src)
    if digest is None:
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
            # Seules passent les variables de RÉSEAU/CA : sans elles, un runner derrière un proxy ou une CA interne ferait
            # échouer la relecture pour une cause qui n'a rien à voir avec la visibilité du package.
            env = {k: v for k, v in os.environ.items() if k in VARIABLES_RESEAU}
            env.update(PATH=os.environ.get("PATH", ""), HOME=vide, DOCKER_CONFIG=vide)
            anonyme = _crane(run, "digest", dst, env=env)
        except CopieError as e:
            raise CopieError(f"{dst} illisible en anonyme — cause probable : package ghcr privé (Package settings > "
                             f"Change visibility ; les pulls anonymes du pod de build feraient 401) ; sinon réseau ou CA. {e}") from None
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
