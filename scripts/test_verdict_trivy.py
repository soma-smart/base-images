#!/usr/bin/env python3
"""Exerce `verdict_trivy.py` dans ses modes d'ECHEC : chaque cas est un chemin par lequel un scan sortirait VERT sans rien prouver."""
import sys
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
    return n


if __name__ == "__main__":
    print(f"OK — {jouer()} cas de refus + nominal")
