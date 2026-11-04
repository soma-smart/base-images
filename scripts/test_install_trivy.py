#!/usr/bin/env python3
"""Exerce `install_trivy.sh` : le chemin nominal ET chaque chemin par lequel l'installation sortirait VERTE sans rien prouver
(somme fausse, ligne de somme absente, version invalide, téléchargement en échec).

Le vrai `curl` est remplacé par un faux, posé en tête du PATH : il sert des fichiers locaux et journalise ses arguments, de sorte
qu'on vérifie AUSSI les flags de reprise (`--retry-all-errors`), qu'aucun test réseau ne peut observer.
Linux uniquement (`sha256sum` GNU) : un test « sauté » ne doit jamais se lire comme un vert, donc on échoue franchement ailleurs.
"""
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).with_name("install_trivy.sh")
VERSION = "0.76.1"
ARCHIVE = f"trivy_{VERSION}_Linux-64bit.tar.gz"

FAUX_CURL = r"""#!/usr/bin/env bash
# Faux curl : journalise les arguments, sert un fichier local selon le NOM de l'URL, ou échoue comme un DNS (exit 6).
echo "$*" >> "$FAUX_CURL_JOURNAL"
[ -z "${FAUX_CURL_ECHEC:-}" ] || exit 6
sortie=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in -o) sortie="$2"; shift ;; http*) url="$1" ;; esac
  shift
done
cp "$FAUX_CURL_FIXTURES/$(basename "$url")" "$sortie"
"""


def archive_bytes():
    """Un tar.gz contenant un `trivy` factice (script shell), comme la vraie archive (binaire à la racine)."""
    contenu = f"#!/bin/sh\necho 'Version: {VERSION}'\n".encode()
    tampon = io.BytesIO()
    with tarfile.open(fileobj=tampon, mode="w:gz") as t:
        for nom, octets, mode in (("trivy", contenu, 0o755), ("LICENSE", b"x", 0o644)):
            info = tarfile.TarInfo(nom)
            info.size, info.mode = len(octets), mode
            t.addfile(info, io.BytesIO(octets))
    return tampon.getvalue()


def lancer(version_fichier=f"{VERSION}\n", somme=None, ligne_somme=True, echec_curl=False):
    """Monte un faux dépôt (script + `.trivy-version`) et un faux curl, lance le script, renvoie (code, sortie, ctx)."""
    tmp = Path(tempfile.mkdtemp())
    try:
        depot, fixtures, fausbin, home = tmp / "depot", tmp / "fixtures", tmp / "bin", tmp / "home"
        for d in (depot / "scripts", fixtures, fausbin, home):
            d.mkdir(parents=True)
        shutil.copy(SCRIPT, depot / "scripts" / "install_trivy.sh")
        (depot / ".trivy-version").write_text(version_fichier)

        archive = archive_bytes()
        (fixtures / ARCHIVE).write_bytes(archive)
        sha = somme or hashlib.sha256(archive).hexdigest()
        ligne = f"{sha}  {ARCHIVE}\n" if ligne_somme else f"{sha}  autre_fichier.tar.gz\n"
        (fixtures / f"trivy_{VERSION}_checksums.txt").write_text(ligne)

        curl = fausbin / "curl"
        curl.write_text(FAUX_CURL)
        curl.chmod(0o755)
        journal, gh_path = tmp / "curl.log", tmp / "github_path"
        env = {"PATH": f"{fausbin}:/usr/bin:/bin", "HOME": str(home), "GITHUB_PATH": str(gh_path),
               "FAUX_CURL_JOURNAL": str(journal), "FAUX_CURL_FIXTURES": str(fixtures)}
        if echec_curl:
            env["FAUX_CURL_ECHEC"] = "1"
        r = subprocess.run(["bash", str(depot / "scripts" / "install_trivy.sh")], env=env, capture_output=True, text=True)
        appels = journal.read_text().splitlines() if journal.exists() else []
        ctx = {"appels": appels, "binaire": (home / ".local/bin/trivy").exists(),
               "github_path": gh_path.read_text() if gh_path.exists() else "", "home": str(home)}
        return r.returncode, r.stdout + r.stderr, ctx
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def verifie(condition, message):
    if not condition:
        print(f"ECHEC: {message}")
        sys.exit(1)


def refuse(nom, fragment=None, **kw):
    """L'installation DOIT échouer, sans binaire et sans toucher à GITHUB_PATH."""
    code, sortie, ctx = lancer(**kw)
    verifie(code != 0, f"{nom} : sortie 0 alors que l'installation devait échouer")
    verifie(not ctx["binaire"], f"{nom} : un binaire a été installé malgré l'échec")
    verifie(ctx["github_path"] == "", f"{nom} : GITHUB_PATH modifié malgré l'échec")
    if fragment:
        verifie(fragment in sortie, f"{nom} : message attendu '{fragment}' absent de : {sortie.strip()[-300:]}")
    return ctx


def main():
    if shutil.which("sha256sum") is None:
        print("ERREUR: sha256sum absent (Linux requis) — test NON joué, ce n'est pas un vert", file=sys.stderr)
        return 2

    # --- nominal : binaire installé, GITHUB_PATH renseigné, URLs de la version du fichier, reprise sur toute erreur
    code, sortie, ctx = lancer()
    verifie(code == 0, f"nominal : échec inattendu : {sortie.strip()[-300:]}")
    verifie(ctx["binaire"], "nominal : binaire absent")
    verifie(ctx["github_path"].strip().endswith("/.local/bin"), f"nominal : GITHUB_PATH inattendu : {ctx['github_path']!r}")
    verifie(f"Version: {VERSION}" in sortie, "nominal : `trivy --version` n'a pas été affiché")
    verifie(len(ctx["appels"]) == 2, f"nominal : 2 téléchargements attendus, vu {len(ctx['appels'])}")
    for appel in ctx["appels"]:
        verifie(f"/releases/download/v{VERSION}/" in appel, f"nominal : URL hors de la version épinglée : {appel}")
        for flag in ("--retry 3", "--retry-all-errors", "--retry-delay 5", "-fsSL"):
            verifie(flag in appel, f"nominal : flag {flag} absent de : {appel}")

    # --- la version vient du FICHIER : CRLF et saut de ligne final sont tolérés
    code, sortie, _ = lancer(version_fichier=f"{VERSION}\r\n")
    verifie(code == 0, f"CRLF : échec inattendu : {sortie.strip()[-200:]}")

    # --- modes d'échec : chacun serait un faux vert
    refuse("somme fausse", "FAILED", somme="0" * 64)
    refuse("ligne de somme absente", ligne_somme=False)
    ctx = refuse("téléchargement en échec (DNS)", echec_curl=True)
    verifie(len(ctx["appels"]) >= 1, "téléchargement en échec : curl n'a même pas été appelé")
    for invalide in ("0.76", "v0.76.1", "0.76.1-rc1", "0.76.1;id", "", "latest", "0.76.1 0.77.0"):
        ctx = refuse(f"version invalide {invalide!r}", "doit contenir X.Y.Z", version_fichier=invalide)
        verifie(ctx["appels"] == [], f"version invalide {invalide!r} : curl appelé alors que la valeur était refusée")

    print("OK: install_trivy.sh — nominal, CRLF, et 10 modes d'échec (somme fausse, somme absente, DNS, 7 versions invalides)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
