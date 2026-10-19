#!/usr/bin/env python3
"""Exerce `verdict_trivy.py` dans ses modes d'ECHEC : chaque cas est un chemin par lequel un scan sortirait VERT sans rien prouver."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from verdict_trivy import VerdictError, verdict  # noqa: E402

REF = "docker.io/library/alpine@sha256:" + "a" * 64


def rapport(**sur):
    r = {"SchemaVersion": 2, "ArtifactName": REF,
         "Metadata": {"OS": {"Family": "alpine", "Name": "3.24.2"}},
         "Results": [{"Class": "os-pkgs", "Target": "x (alpine 3.24.2)", "Packages": [{"Name": "musl"}] * 16}]}
    r.update(sur)
    return r


def refuse(nom, r, fragment):
    try:
        verdict(r, REF)
    except VerdictError as e:
        assert fragment in str(e), f"{nom} : message sans « {fragment} » : {e}"
        return
    raise AssertionError(f"{nom} : aucun refus")


def jouer():
    n = 0
    assert "couverture OK" in verdict(rapport(), REF) and "16 paquets" in verdict(rapport(), REF), "nominal"
    refuse("schéma", rapport(SchemaVersion=3), "schéma"); n += 1
    refuse("autre artefact", rapport(ArtifactName="docker.io/library/alpine:3.24"), "attendu"); n += 1
    refuse("sans OS", rapport(Metadata={}), "aucun OS"); n += 1
    refuse("inventaire vide (OS reconnu, rien énuméré)", rapport(Results=[{"Class": "os-pkgs", "Packages": []}]), "aucun paquet"); n += 1
    refuse("aucun résultat", rapport(Results=[]), "aucun paquet"); n += 1
    refuse("résultat non os-pkgs seulement", rapport(Results=[{"Class": "lang-pkgs", "Packages": [{"Name": "x"}]}]), "aucun paquet"); n += 1
    refuse("fin de support", rapport(Metadata={"OS": {"Family": "alpine", "Name": "3.20.10", "EOSL": True}}), "FIN DE SUPPORT"); n += 1
    vuln = {"Class": "os-pkgs", "Target": "t", "Packages": [{"Name": "p"}],
            "Vulnerabilities": [{"Severity": "HIGH", "VulnerabilityID": "CVE-1", "PkgName": "p", "InstalledVersion": "1", "FixedVersion": "2"}]}
    refuse("CVE corrigeable", rapport(Results=[vuln]), "1 vulnérabilité"); n += 1
    # Une CVE hors `os-pkgs` COMPTE (la classe n'est pas filtrée) : une dépendance de langue vulnérable bloque aussi.
    lang = {"Class": "lang-pkgs", "Target": "l", "Vulnerabilities": vuln["Vulnerabilities"]}
    propre = {"Class": "os-pkgs", "Target": "t", "Packages": [{"Name": "p"}]}
    refuse("CVE lang-pkgs", rapport(Results=[propre, lang]), "1 vulnérabilité"); n += 1
    # Un seul inventaire os-pkgs non vide suffit (max, pas somme ni min) ; le résumé porte ce nombre.
    vide = {"Class": "os-pkgs", "Target": "v", "Packages": []}
    r = verdict(rapport(Results=[vide, {"Class": "os-pkgs", "Target": "w", "Packages": [{"Name": "x"}] * 16}]), REF)
    assert "paquets=16" in r, r
    refuse("Packages None", rapport(Results=[{"Class": "os-pkgs", "Packages": None}]), "aucun paquet"); n += 1
    refuse("Metadata.OS None", rapport(Metadata={"OS": None}), "aucun OS"); n += 1
    # Le conseil de remédiation propre au socle est restitué dans le refus.
    try:
        verdict(rapport(Results=[vuln]), REF, "CONSEIL-DU-SOCLE")
    except VerdictError as e:
        assert "CONSEIL-DU-SOCLE" in str(e), e
        n += 1
    # La CLI : un refus DOIT sortir en code ≠ 0 avec `ERREUR:` (les workflows appellent la CLI, pas `verdict()`).
    cli = str(Path(__file__).with_name("verdict_trivy.py"))
    with tempfile.TemporaryDirectory() as d:
        def lancer(contenu, *args):
            f = Path(d) / "t.json"
            f.write_text(contenu if isinstance(contenu, str) else json.dumps(contenu), encoding="utf-8")
            return subprocess.run([sys.executable, cli, str(f), *args], capture_output=True, text=True)
        r = lancer(rapport(SchemaVersion=3), REF)
        assert r.returncode != 0 and "ERREUR:" in r.stderr, (r.returncode, r.stderr)
        r = lancer(rapport(), REF)
        assert r.returncode == 0 and "couverture OK" in r.stdout, (r.returncode, r.stdout, r.stderr)
        r = lancer("pas du json", REF)
        assert r.returncode != 0 and "ERREUR:" in r.stderr, "JSON invalide : doit refuser proprement"
        r = subprocess.run([sys.executable, cli, str(Path(d) / "absent.json"), REF], capture_output=True, text=True)
        assert r.returncode != 0 and "ERREUR:" in r.stderr, "fichier absent : doit refuser proprement"
        r = subprocess.run([sys.executable, cli, str(Path(d) / "t.json")], capture_output=True, text=True)
        assert r.returncode != 0, "un seul argument : doit afficher l'usage et échouer"
        n += 5
    return n


if __name__ == "__main__":
    print(f"OK — {jouer()} cas de refus + nominal")
