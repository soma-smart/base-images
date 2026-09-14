#!/usr/bin/env python3
"""Exerce `verifier-lookups.py` dans ses modes d'ECHEC, pas sur son chemin heureux.

⚠️ UN GATE ANTI-ECHEC-SILENCIEUX NON TESTE EST UN ECHEC SILENCIEUX DE PLUS. Chaque cas
ci-dessous correspond a un chemin par lequel le gate rendrait VERT sans avoir rien
prouve — deux d'entre eux etaient ouverts dans la premiere redaction du script.
"""
import subprocess
import sys
import tempfile
from pathlib import Path

GATE = Path(__file__).with_name("verifier-lookups.py")
DEPOT_OK = '{"msg":"Repository finished","repository":"soma-smart/multica-runtime"}'

CAS = [
    # (nom, lignes du journal, code attendu, fragment attendu dans la sortie)
    ("nominal", [DEPOT_OK, '{"msg":"PR created"}'], 0, "aucune resolution en echec"),
    # Les QUATRE familles d'avertissement de lookupUpdates, une par une.
    ("famille_lookup", [DEPOT_OK,
     '{"warnings":["Failed to look up github-releases package aquasecurity/trivy"]}'],
     1, "aquasecurity/trivy"),
    ("famille_digest", [DEPOT_OK,
     '{"warnings":["Could not determine new digest for update (docker package base/python-slim)"]}'],
     1, "Could not determine new digest"),
    ("famille_version_matching", [DEPOT_OK,
     '{"warnings":["Can\'t find version matching 1.2 for docker package foo"]}'],
     1, "Can't find version"),
    ("famille_version_tag", [DEPOT_OK,
     '{"warnings":["Can\'t find version with tag stable for npm package bar"]}'],
     1, "Can't find version"),
    # L'avertissement sous forme d'OBJET et non de chaine.
    ("avertissement_objet", [DEPOT_OK,
     '{"warnings":[{"topic":"x","message":"Failed to look up docker package foo"}]}'],
     1, "resolution en echec"),
    # Les gardes positifs : chacun refuse un journal qui ne prouve rien.
    ("journal_vide", [], 1, "0 entree JSON"),
    ("console_ansi", [" WARN: Package lookup failures", '    "warnings": ["Failed to look up x"],'],
     1, "0 entree JSON"),
    ("tronque_sur_l_avertissement",
     [DEPOT_OK, '{"warnings":["Failed to look up github-releases package aquasecurity/trivy"'],
     1, "tronque"),
    ("aucun_depot_traite",
     ['{"msg":"Renovate config"}', '{"msg":"Autodiscovered 0 repositories"}'],
     1, "AUCUN depot"),
]


def jouer():
    echecs = 0
    with tempfile.TemporaryDirectory() as bac:
        for nom, lignes, code_attendu, fragment in CAS:
            chemin = Path(bac) / f"{nom}.ndjson"
            chemin.write_text("\n".join(lignes) + ("\n" if lignes else ""), encoding="utf-8")
            r = subprocess.run([sys.executable, str(GATE), str(chemin)],
                               capture_output=True, text=True)
            sortie = r.stdout + r.stderr
            ok = r.returncode == code_attendu and fragment in sortie
            print(f"  {'OK  ' if ok else 'ECHEC'} {nom:<28} exit={r.returncode} "
                  f"(attendu {code_attendu})")
            if not ok:
                print(f"        fragment attendu : {fragment!r}")
                print(f"        sortie : {sortie.strip()[:200]!r}")
                echecs += 1
        # Le fichier absent se teste hors de la boucle : il ne doit pas exister.
        r = subprocess.run([sys.executable, str(GATE), str(Path(bac) / "absent.ndjson")],
                           capture_output=True, text=True)
        ok = r.returncode == 1 and "illisible" in (r.stdout + r.stderr)
        print(f"  {'OK  ' if ok else 'ECHEC'} {'fichier_absent':<28} exit={r.returncode} (attendu 1)")
        echecs += 0 if ok else 1
    return echecs


if __name__ == "__main__":
    print("verifier-lookups.py — contre-tests")
    n = jouer()
    print(f"\n{'tous les cas passent' if n == 0 else f'{n} cas EN ECHEC'}")
    sys.exit(1 if n else 0)
