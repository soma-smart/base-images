#!/usr/bin/env python3
"""Verdict d'un rapport Trivy (`--format json --list-all-pkgs`) : la COUVERTURE d'abord, les CVE ensuite.

⚠️ Le verdict est rendu ici, PAS par `trivy --exit-code 1`. Un scan qui n'analyse RIEN sort 0 : le gate serait vert par
AVEUGLEMENT, et un gate incapable de distinguer « rien trouvé » de « rien cherché » ne prouve rien. Extrait de
`build-python-slim.yml` (qui le portait en ligne) pour que tout socle partage le MÊME verdict.

Usage : verdict_trivy.py <trivy.json> <référence attendue> [conseil de remédiation] — code 0 = couverture prouvée ET aucune CVE CRITICAL/HIGH corrigeable.
"""
import json
import sys


class VerdictError(RuntimeError):
    pass


def verdict(rapport, attendu, conseil=None):
    """Renvoie la ligne de résumé, ou lève VerdictError. `rapport` : dict issu de `trivy image --format json`."""
    # Le schéma d'abord : un changement de format amont transformerait toutes les assertions suivantes en lectures de clés
    # absentes, donc en silence.
    schema = rapport.get("SchemaVersion")
    if schema != 2:
        raise VerdictError(f"schéma de rapport Trivy inattendu ({schema!r}, attendu 2) — les assertions suivantes ne veulent plus rien dire.")
    artefact = rapport.get("ArtifactName")
    if artefact != attendu:
        raise VerdictError(f"Trivy a scanné '{artefact}', attendu '{attendu}'.")
    os_info = (rapport.get("Metadata") or {}).get("OS") or {}
    famille = os_info.get("Family")
    if not famille:
        raise VerdictError("Trivy n'a identifié aucun OS dans l'image.")
    resultats = rapport.get("Results") or []
    paquets = max((len(r.get("Packages") or []) for r in resultats if r.get("Class") == "os-pkgs"), default=0)
    if paquets == 0:
        # « L'OS a été identifié » NE SUFFIT PAS : la détection lit `/etc/os-release`, indépendamment de toute énumération.
        raise VerdictError("aucun paquet OS énuméré. Trivy a reconnu l'OS mais n'a comparé AUCUN paquet aux avis de sécurité — "
                           "base de paquets absente ou vide. Le rapport est vide par aveuglement, pas par propreté.")
    if os_info.get("EOSL"):
        raise VerdictError(f"la distribution ({famille} {os_info.get('Name')}) est en FIN DE SUPPORT : plus aucun avis n'est publié, "
                           "un scan vert ne prouve plus rien. Changer de base amont.")
    couverture = f"couverture OK — artefact={artefact} os={famille} {os_info.get('Name')} paquets={paquets} cibles={len(resultats)}"
    bloquantes = [(c.get("Target"), v) for c in resultats for v in (c.get("Vulnerabilities") or [])]
    if bloquantes:
        # La couverture est imprimée AUSSI sur le chemin d'échec : c'est là qu'on en a besoin pour savoir ce qui a été comparé.
        print(couverture)
        for cible, v in bloquantes:
            print(f"  {v['Severity']:8} {v['VulnerabilityID']:20} {v.get('PkgName')} {v.get('InstalledVersion')} "
                  f"→ {v.get('FixedVersion')}  [{cible}]")
        # Aucun mécanisme d'exception, délibérément : une base est le seul endroit où une CVE corrigeable se corrige VRAIMENT,
        # et une tolérance posée sur le socle serait opposable à tous ses consommateurs d'un coup.
        raise VerdictError(f"{len(bloquantes)} vulnérabilité(s) CRITICAL/HIGH corrigeable(s). Sur un SOCLE, elles se corrigent : "
                           + (conseil or "reconstruire ou bumper la base amont ; n'attendre l'amont qu'en dernier recours."))
    return couverture + f"\naucune vulnérabilité bloquante — {paquets} paquets OS comparés."


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)
    try:
        with open(sys.argv[1], encoding="utf-8") as f:
            print(verdict(json.load(f), sys.argv[2], sys.argv[3] if len(sys.argv) == 4 else None))
    except (VerdictError, OSError, ValueError) as e:
        sys.exit(f"ERREUR: {e}")
