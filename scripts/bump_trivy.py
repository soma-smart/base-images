#!/usr/bin/env python3
"""Fait monter `.trivy-version` quand une release stable et MÛRE de Trivy est parue, et ouvre la PR correspondante.

Appelé par `.github/workflows/bump-trivy.yml` (cron quotidien). Tests : `scripts/test_bump_trivy.py`.

⚠️ POURQUOI CE SCRIPT ET PAS RENOVATE : `base-images` n'est pas autodécouvert par Renovate (README : l'installation de
l'app `soma-base-bumper` = les dépôts consommateurs, et l'y ajouter applique toute la politique de `renovate-config.js`,
dont l'automerge `github-actions`, à un dépôt qui porte cette config). Sans suivi, la version de Trivy gèle en silence.

⚠️ CHAQUE GARDE ÉVITE UN FAUX « À JOUR », la panne silencieuse de cette classe de script :
  - tout échec de lecture (réseau, quota, JSON inattendu, liste vide, aucune release stable reconnue, date illisible,
    release mûre sans ses fichiers) LÈVE `BumpError` → job rouge. Jamais « rien à faire » par défaut ;
  - release STABLE seulement (ni brouillon, ni pré-release, tag strictement `vX.Y.Z` : la valeur finit dans un nom de
    branche et une URL), MÛRE (≥ 3 jours, comme `minimumReleaseAge` côté Renovate), jamais de retour en arrière ;
  - la requête à l'API de Trivy est ANONYME : l'organisation `aquasecurity` a une IP allow list qui rejette les requêtes
    AUTHENTIFIÉES venant de notre IP (documenté dans `renovate-config.js`). Un jeton ne l'aiderait pas, il la casserait.
    Le jeton ne sert qu'à NOTRE dépôt.

⚠️ GITHUB_TOKEN : ni la PR ni le push ne déclenchent les workflows `pull_request` (règle GitHub). Les CI sont donc lancées
explicitement par `workflow_dispatch` sur la branche — SAUF `mirror-dhi.yml`, qui publie vers Harbor sans garde de branche.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

FICHIER = Path(__file__).resolve().parent.parent / ".trivy-version"
URL_RELEASES = "https://api.github.com/repos/aquasecurity/trivy/releases?per_page=30"
AGE_MIN = timedelta(days=3)
# build + scan sans publier (leurs steps de publication exigent `ref == main`). JAMAIS `mirror-dhi.yml`.
WORKFLOWS_CI = ("build-python-slim.yml", "copie-alpine.yml")
RE_VERSION = re.compile(r"\d+\.\d+\.\d+")
RE_TAG = re.compile(r"v(\d+)\.(\d+)\.(\d+)")


class BumpError(Exception):
    """Situation où l'on ne peut pas CONCLURE : le job doit être rouge, jamais « à jour »."""


def version_tuple(texte):
    if not RE_VERSION.fullmatch(texte or ""):
        raise BumpError(f"version invalide : {texte!r} (attendu X.Y.Z)")
    return tuple(int(x) for x in texte.split("."))


def lire_courante(chemin=FICHIER):
    lignes = [ligne.strip() for ligne in Path(chemin).read_text().splitlines() if ligne.strip()]
    if len(lignes) != 1:
        raise BumpError(f"{chemin} doit contenir UNE ligne X.Y.Z (trouvé {len(lignes)} ligne(s) non vide(s))")
    version_tuple(lignes[0])
    return lignes[0]


def releases_anonymes(ouvrir=urllib.request.urlopen, essais=3, pause=5, dormir=time.sleep):
    """Dernières releases de Trivy. ⚠️ AUCUN en-tête Authorization (cf. l'en-tête du module) : ne jamais en ajouter."""
    requete = urllib.request.Request(
        URL_RELEASES, headers={"Accept": "application/vnd.github+json", "User-Agent": "base-images-bump-trivy"})
    derniere = None
    for essai in range(1, essais + 1):
        try:
            with ouvrir(requete, timeout=20) as reponse:
                return json.loads(reponse.read().decode())
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                raise BumpError(f"API GitHub : HTTP {e.code} (quota anonyme ou refus d'IP) — pas de nouvel essai") from e
            derniere = f"HTTP {e.code}"
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            derniere = f"{type(e).__name__}: {e}"
        if essai < essais:
            dormir(pause)
    raise BumpError(f"impossible de lire les releases de Trivy après {essais} essais ({derniere})")


def date_publication(valeur):
    try:
        return datetime.strptime(valeur, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as e:
        raise BumpError(f"published_at illisible : {valeur!r}") from e


def choisir(releases, courante, maintenant):
    """Renvoie (cible | None, raison). `courante` : tuple. Lève BumpError dès qu'on ne peut pas conclure."""
    if not isinstance(releases, list) or not releases:
        raise BumpError(f"réponse inattendue de l'API (liste vide ou autre type : {type(releases).__name__})")
    stables = []
    for r in releases:
        if not isinstance(r, dict) or "tag_name" not in r:
            raise BumpError("entrée de release sans `tag_name` : format de l'API changé ?")
        m = RE_TAG.fullmatch(str(r["tag_name"]))
        if not m or r.get("draft") or r.get("prerelease"):
            continue  # nightly, rc, brouillon : jamais proposés
        stables.append((tuple(int(x) for x in m.groups()), r))
    if not stables:
        raise BumpError(f"aucune release stable `vX.Y.Z` reconnue parmi {len(releases)} : format de l'API changé ?")

    plus_recente = max(v for v, _ in stables)
    candidates = [(v, r) for v, r in stables if v > courante]
    if not candidates:
        return None, f"à jour : la plus récente release stable est {'.'.join(map(str, plus_recente))}"
    murs = [(v, r) for v, r in candidates if maintenant - date_publication(r.get("published_at")) >= AGE_MIN]
    if not murs:
        nouvelle = '.'.join(map(str, max(v for v, _ in candidates)))
        return None, f"{nouvelle} est parue depuis moins de {AGE_MIN.days} jours : on attend la maturité"
    v, r = max(murs, key=lambda x: x[0])
    version = ".".join(map(str, v))
    noms = {a.get("name") for a in r.get("assets", []) if isinstance(a, dict)}
    attendus = {f"trivy_{version}_Linux-64bit.tar.gz", f"trivy_{version}_checksums.txt"}
    if not attendus <= noms:
        raise BumpError(f"{version} est mûre mais ses fichiers {sorted(attendus - noms)} sont absents : "
                        "format de publication changé ? (pas de bump sur une release qu'on ne sait pas installer)")
    return {"version": version, "publiee": r["published_at"], "url": r.get("html_url", "")}, "mise à jour disponible"


def corps_pr(courante, cible, branche):
    return f"""## Trivy {courante} → {cible['version']}

Ouverte automatiquement par `bump-trivy.yml` : Renovate ne suit pas `base-images` (README).

- **Release** : {cible['url'] or '(lien absent)'} — publiée le {cible['publiee']}, stable, âgée d'au moins {AGE_MIN.days} jours, archive et fichier de sommes présents.
- **Changement** : `.trivy-version` seul.

### CI
Un workflow ne déclenche pas les runs `pull_request` avec le `GITHUB_TOKEN` : `bump-trivy.yml` a donc lancé à la main `{'` et `'.join(WORKFLOWS_CI)}` sur la branche `{branche}` (build + scan, **aucune publication** : leurs steps de publication sont limités à `main`). Leurs résultats apparaissent dans les checks de cette PR une fois terminés.
⚠️ `mirror-dhi` n'est volontairement PAS lancé (il publie vers Harbor) : sa preuve est son run de 02:00 UTC suivant le merge.

### Avant de merger
- Checks verts **sur le dernier commit**.
- `scripts/verdict_trivy.py` exige le schéma JSON 2 de Trivy et échoue franchement sinon.

### Refuser cette version
Fermer la PR sans merger : le workflow ne reproposera PAS cette version (une version plus récente, si).
"""


class Github:
    """API REST de NOTRE dépôt, avec le jeton du workflow. Jamais utilisée pour interroger Trivy."""

    def __init__(self, depot, jeton, ouvrir=urllib.request.urlopen):
        self.depot, self.jeton, self.ouvrir = depot, jeton, ouvrir

    def __call__(self, methode, chemin, corps=None):
        requete = urllib.request.Request(
            f"https://api.github.com/repos/{self.depot}{chemin}", method=methode,
            data=None if corps is None else json.dumps(corps).encode(),
            headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {self.jeton}",
                     "User-Agent": "base-images-bump-trivy", "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with self.ouvrir(requete, timeout=30) as reponse:
                brut = reponse.read().decode()
                return json.loads(brut) if brut else None
        except urllib.error.HTTPError as e:
            detail = e.read().decode()[:300] if hasattr(e, "read") else ""
            aide = ""
            if methode == "POST" and chemin == "/pulls" and e.code in (403, 422):
                aide = (" — si le message dit que les Actions ne peuvent pas créer de PR : Settings > Actions > General > "
                        "« Allow GitHub Actions to create and approve pull requests », au niveau du dépôt ET de l'organisation")
            raise BumpError(f"{methode} {chemin} : HTTP {e.code} {detail}{aide}") from e


def git(args, tolerer=(0,)):
    code = subprocess.run(["git", *args], check=False).returncode
    if code not in tolerer:
        raise BumpError(f"git {' '.join(args[:2])} a échoué (code {code})")
    return code


def ouvrir_pr(courante, cible, *, api, executer_git, proprietaire):
    """Idempotent : une PR existante pour cette version (ouverte, fusionnée OU fermée = refus) n'est jamais recréée."""
    branche = f"bump/trivy-{cible['version']}"
    if api("GET", f"/pulls?head={proprietaire}:{branche}&state=all"):
        print(f"::notice::une PR existe déjà pour {branche} (ouverte, fusionnée ou fermée = refus) : rien à faire")
        return "existe"
    # Branche déjà poussée mais sans PR (échec entre les deux lors d'un run précédent) : on ne repousse pas, on ouvre la PR.
    if executer_git(["ls-remote", "--exit-code", "--heads", "origin", f"refs/heads/{branche}"], tolerer=(0, 2)) != 0:
        executer_git(["switch", "-c", branche])
        executer_git(["add", ".trivy-version"])
        executer_git(["-c", "user.name=github-actions[bot]", "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
                      "commit", "-m", f"chore(trivy): {courante} → {cible['version']}"])
        executer_git(["push", "origin", branche])
    api("POST", "/pulls", {"title": f"chore(trivy): {courante} → {cible['version']}", "head": branche, "base": "main",
                           "body": corps_pr(courante, cible, branche)})
    for workflow in WORKFLOWS_CI:
        api("POST", f"/actions/workflows/{workflow}/dispatches", {"ref": branche})
    return "ouverte"


def ecrire_sortie(**valeurs):
    chemin = os.environ.get("GITHUB_OUTPUT")
    if chemin:
        with open(chemin, "a") as f:
            for cle, valeur in valeurs.items():
                f.write(f"{cle}={valeur}\n")


def main(argv=None, *, fichier=FICHIER, maintenant=None, releases=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--simuler-version-courante", metavar="X.Y.Z",
                        help="SIMULATION : traite cette version comme courante, n'écrit rien et ne pousse rien ; "
                             "affiche la PR qui serait ouverte")
    args = parser.parse_args(argv)

    courante = args.simuler_version_courante or lire_courante(fichier)
    liste = releases if releases is not None else releases_anonymes()
    cible, raison = choisir(liste, version_tuple(courante), maintenant or datetime.now(timezone.utc))
    print(f"version courante : {courante} — {raison}")
    ecrire_sortie(bump="true" if cible else "false", courante=courante, cible=cible["version"] if cible else "")
    if not cible:
        return 0

    branche = f"bump/trivy-{cible['version']}"
    if args.simuler_version_courante:
        print(f"[SIMULATION] rien n'est écrit, poussé ni dispatché. Il serait fait :\n"
              f"  branche {branche}, commit « chore(trivy): {courante} → {cible['version']} » (`.trivy-version`)\n"
              f"  PR vers main, puis workflow_dispatch de {', '.join(WORKFLOWS_CI)} sur {branche}\n"
              f"--- corps de la PR ---\n{corps_pr(courante, cible, branche)}")
        return 0

    depot = os.environ.get("GITHUB_REPOSITORY", "soma-smart/base-images")
    jeton = os.environ.get("GITHUB_TOKEN")
    if not jeton:
        raise BumpError("GITHUB_TOKEN absent : impossible d'ouvrir la PR")  # avant toute écriture : rien ne reste modifié
    Path(fichier).write_text(cible["version"] + "\n")
    etat = ouvrir_pr(courante, cible, api=Github(depot, jeton), executer_git=git, proprietaire=depot.split("/")[0])
    print(f"PR {etat} pour {branche}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BumpError as e:
        print(f"::error::{e}", file=sys.stderr)
        sys.exit(1)
