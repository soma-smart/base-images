#!/usr/bin/env python3
"""Copie une base de Harbor vers ghcr PAR DIGEST et refuse si le digest ghcr diffère.

⚠️ POURQUOI PAR DIGEST ET PAS PAR TAG. Le tag Harbor est mouvant : entre « lire le digest »
et « copier », un rebuild peut le déplacer, et l'on publierait sur ghcr un objet que l'on n'a
pas vérifié. On fige le digest d'abord, on copie CE digest, puis on relit la destination.

⚠️ POURQUOI L'ÉGALITÉ EST ASSERTÉE. Les consommateurs épinglent `repo:tag@sha256:…`. Une copie
qui recompresse ou convertit le format produit un AUTRE digest : l'épingle ne résoudrait plus
sur ghcr, sans aucune erreur de copie. Le contrôle est donc la seule preuve que « même image »
est vrai.

Usage : copie_ghcr.py <source tag> <destination tag> — code 0 = digests égaux.
"""
import subprocess
import sys


class CopieError(RuntimeError):
    pass


def _crane(run, *args):
    r = run(["crane", *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise CopieError(f"crane {' '.join(args)} a échoué (code {r.returncode}) : {(r.stderr or '').strip()}")
    return (r.stdout or "").strip()


def copier_et_verifier(src, dst, run=subprocess.run):
    digest = _crane(run, "digest", src)
    if not digest.startswith("sha256:"):
        raise CopieError(f"digest source illisible pour {src} : {digest!r}")
    depot = src.rsplit(":", 1)[0]
    _crane(run, "copy", f"{depot}@{digest}", dst)
    obtenu = _crane(run, "digest", dst)
    if obtenu != digest:
        raise CopieError(f"digest différent après copie : source {digest}, destination {obtenu} ({dst})")
    return digest


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    try:
        print(copier_et_verifier(sys.argv[1], sys.argv[2]))
    except CopieError as e:
        sys.exit(f"ERREUR: {e}")
