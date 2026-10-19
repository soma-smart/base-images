# base-images

Golden base images de SOMA : **mirror durci des [Docker Hardened Images](https://www.docker.com/products/hardened-images/) (DHI)** vers Harbor, pour l'industrialisation de la remédiation des CVE.

## Principe

Les DHI sont des images near-zero-CVE (SBOM + VEX + provenance SLSA signés), gratuites/open-source (Apache 2.0) depuis 12/2025. Ce repo les **mirror** dans le projet Harbor `base` et les rend consommables par les apps maison.

```
dhi.io/python:<ver>  ──(mirror nocturne)──▶  registry-dev.soma-smart.cloud/base/python:<ver>
                                                        │
                        apps: FROM …/base/python:<ver>@sha256:<digest>  (digest-pin Renovate)
```

- **Source DHI** : registre dédié **`dhi.io`** (PAS `docker.io/dhi`). Ex. `dhi.io/python:3.13`. Auth requise même en gratuit : `docker login dhi.io` avec identifiants Docker Hub + **PAT** comme mot de passe.
- **Tag mouvant** : `base/python:<ver>` est **redigesté à chaque rebuild DHI**. L'immutabilité au pull est assurée côté consommateur par le **digest-pin** (`@sha256:…`), suivi automatiquement par Renovate.
- **Gate Trivy** : avant push, une CVE fixable Critical/High fait échouer le job → on ne propage jamais une base régressée. ⚠️ **Les deux gates ne se valent pas** : `mirror-dhi` s'en remet encore à `trivy … --exit-code 1`, qui ne distingue pas « rien trouvé » de « rien cherché » ; `build-python-slim` rend désormais son verdict explicitement (couverture prouvée avant absence de CVE, cf. plus bas). Aligner le premier sur le second reste à faire.
- **Versions maintenues** : `3.11`, `3.12`, `3.13`, `3.14` (union des versions utilisées par les apps).

## `base/python-slim` — base scientifique (non-distroless)

Certaines apps (finops : pandas/scipy/scikit-learn) ont besoin d'un **runtime glibc complet** (libstdc++, libgomp) que le socle DHI **distroless** n'offre pas. Pour elles, une base SLIM durcie **construite** (pas mirrorée) :

```
python:<ver>-slim  ──(build nocturne + libgomp1 + non-root 65532)──▶  base/python-slim:<ver>
                                                        │
                        apps sci: FROM …/base/python-slim:<ver>@sha256:<digest>  (digest-pin Renovate)
```

**Copie ghcr (même digest).** Après le push Harbor, `scripts/copie_ghcr.py` copie `base/python-slim:<ver>` vers `ghcr.io/soma-smart/base/python-slim:<ver>` **par digest**, puis relit la destination **sans identifiants**. Raison : le pod de build des MCP (namespace `arc-mcp`, code non relu) ne peut pas joindre Harbor ; il tire ses bases de ghcr, en anonyme.
- Le package ghcr doit être **public** (geste manuel : Package settings → Change visibility). Tant qu'il est privé, la copie échoue exprès (relecture anonyme) et la check Healthchecks du build reçoit `/fail`.
- Fenêtre de divergence : Harbor est poussé AVANT la copie ; si la copie échoue, ghcr reste sur l'ancien digest jusqu'à la correction (le `/fail` l'annonce).
- Rétention différente : Harbor purge un digest sans tag en ~3 jours, ghcr le garde (nettoyage à prévoir quand le volume le justifie).

- `.github/workflows/build-python-slim.yml` — `docker build python-slim/Dockerfile` (`FROM python:<ver>-slim` **non pinné** + `--pull`) → gate Trivy durci → push. Même robot `base-pusher`, même runner, même tag mouvant + digest-pin consommateur que `base/python`.
- **Le socle applique lui-même les correctifs Debian** (`apt-get dist-upgrade` au build). ⚠️ **Ce n'est pas redondant avec `--pull`** : `--pull` ne fait que reprendre le dernier `python:<ver>-slim` publié par Docker Hub, dont la cadence de reconstruction ne nous appartient pas. Sans le `dist-upgrade`, une DSA publiée aujourd'hui n'entre dans le socle que le jour où Docker Hub reconstruit — et le gate, lui, refuse la base **immédiatement**. C'est exactement l'interblocage vécu du 2026-08-17 au 20 (DSA-6442-1, `util-linux`) : gate rouge quatre nuits, base plus republiée, digest figé, **aucun consommateur du socle capable de produire une image verte**.
- **Le gate ne peut pas être vert par aveuglement.** Le verdict n'est plus `trivy --exit-code 1` mais un contrôle explicite : schéma du rapport, artefact scanné, **inventaire de paquets OS non vide**, distribution non EOSL, puis absence de CVE. Un scan qui n'analyse rien sort `0` — sur un socle qui retire déjà pip et `ensurepip`, c'est un mode de panne réel, pas une hypothèse.
- **Aucun mécanisme d'exception ici, à dessein** : une base est le seul endroit où une CVE corrigeable se corrige vraiment. Une porte de tolérance sur le socle serait opposable à tous ses consommateurs d'un coup.
- Durcissement : **non-root uid 65532** (aligné DHI), `libgomp1` (OpenMP scipy/sklearn), UTF-8 forcé, pas de cache apt. Distroless-like côté sécurité mais garde un shell + glibc pour les wheels natives.
- **Versions** : `3.14` (finops). Étendre la matrice quand une autre app scientifique arrive.
- **Choisir la base** : app standard → `base/python` (distroless, le plus dur) ; app scientifique (scipy/sklearn/pandas lourd, ou qui invoque un binaire système) → `base/python-slim`.

## `base/alpine` — conteneur de job des builds MCP (copie, pas construction)

`docker.io/library/alpine:<X.Y.Z>@sha256:…` (épinglé par la ligne `FROM` de `alpine/Dockerfile`, **bump manuel**) ──(gate Trivy sur CE digest)──▶ `ghcr.io/soma-smart/base/alpine:<X.Y.Z>` (même digest, index multi-architecture entier). Consommateur : le `container: image:` des workflows de `mcp-servers` (namespace `arc-mcp`, qui ne joint ni Harbor ni Docker Hub). Il exécute des étapes d'auteur non relues : une branche Alpine hors support n'y reçoit plus aucun correctif (la 3.20 est sortie de support le 2026-04-01 ; la 3.21 le sera le 2026-11-01 — viser la branche maintenue la plus récente).
- **Workflow** `.github/workflows/copie-alpine.yml` : cron nocturne (relit la visibilité du package et les CVE parues après la copie), push sur `alpine/**`, `workflow_dispatch`. Sur PR : scan seul, jamais de publication.
- **Verdict Trivy** : `scripts/verdict_trivy.py` (partagé avec `build-python-slim`) — couverture prouvée, `EOSL` refusé, CVE fixable Critical/High = échec, sans exception.
- **Écart assumé** : pas de passage par Harbor (son seul consommateur est ghcr) ; on perd le scan-on-push de Harbor, remplacé par ce gate.
- **Gestes manuels** : package ghcr **public** (irréversible) — le premier run est rouge par construction ; secret `HEALTHCHECKS_URL_COPIE_ALPINE` (sinon dead-man's switch inerte, signalé en avertissement).
- ⚠️ **Aucun Renovate ne suit cette chaîne aujourd'hui** : constaté le 2026-10-19, Renovate autodécouvre 8 dépôts, ni `base-images` ni `mcp-servers` n'en font partie. Ni `alpine/Dockerfile`, ni l'épingle du consommateur (`container: image: ghcr.io/soma-smart/base/alpine:<X.Y.Z>@sha256:…`) ne reçoivent de PR. L'alarme est le cron de `copie-alpine` (rouge à la première CVE corrigeable ou à la fin de support) ; au bump, vérifier à la main qu'une version a ≥ 3 jours. Étendre le périmètre de `soma-base-bumper` applique TOUTE la politique de `renovate-config.js` à ces dépôts : décision de Gautier. Une datasource `docker` sur ghcr n'a de toute façon pas d'horodatage.

## Workflow

`.github/workflows/mirror-dhi.yml` — matrix par version : pull DHI → retag → gate Trivy → push Harbor. Idempotent (un digest inchangé = no-op).

### Prérequis (à mettre en place avant d'activer le `schedule`)

1. **Runner ARC** `onprem-dev-base-images` (déclaré dans `infra-datacenter-docs`, app ArgoCD ARC) + repo ajouté à l'installation de la GitHub App `soma-smart-arc-runners`.
2. **Secrets du repo** :
   | Secret | Valeur |
   |---|---|
   | `HARBOR_USERNAME` | nom du robot Harbor `base-pusher` (contient `$`) |
   | `HARBOR_PASSWORD` | secret du robot `base-pusher` |
   | `DOCKERHUB_USERNAME` | compte Docker Hub (pull `dhi.io`) |
   | `DOCKERHUB_PAT` | PAT Docker Hub |
   | `HEALTHCHECKS_URL_BUILD_PYTHON_SLIM` | URL de ping de la check Healthchecks.io du build nocturne (cf. « Surveillance ») |

Une fois les deux prérequis en place, **décommenter le bloc `schedule`** dans le workflow.

### Surveillance du build nocturne (dead-man's switch)

`build-python-slim` a échoué **quatre nuits d'affilée** (2026-08-17 → 20) sans que personne ne le sache. Le coût n'a pas été l'échec — il était justifié — mais son **silence** : la base ne se republiait plus, son digest se figeait, et plus aucun consommateur du socle ne pouvait produire une image verte. La panne a été découverte par quelqu'un qui poussait du code sur un dépôt consommateur.

Le workflow pinge donc une check **Healthchecks.io** à chaque exécution : l'URL nue en cas de succès, `<url>/fail` sinon. C'est le **ping de succès** qui porte la protection — il attrape aussi ce qu'un `if: failure()` ne verrait jamais : job qui ne démarre pas, runner ARC absent, `schedule` désactivé, dépôt sorti de l'installation de l'App GitHub.

Mise en place, une fois : créer la check (période 1 j, grâce ~2 h — le cron est à 03:00 UTC), puis déposer son URL de ping dans le secret `HEALTHCHECKS_URL_BUILD_PYTHON_SLIM`.

⚠️ **Tant que ce secret n'existe pas, le dispositif est INERTE** — et le workflow le dit à chaque run (annotation `::warning::` + encart dans le résumé du job) plutôt que de laisser croire à une protection en place.

⚠️ **Une seule check pour toute la matrice.** Elle ne porte qu'une version aujourd'hui ; si elle s'élargit, un succès `3.15` masquerait un échec `3.14` — il faudra alors une check par version, pas un ping partagé.

---

## Boucle de remédiation automatique (Renovate self-hosted)

Le mirror publie une base **redigestée**, mais ça ne remédie rien tant que les apps épinglent l'**ancien** digest. La **propagation** du nouveau digest vers les apps est assurée par un **Renovate self-hosted** hébergé dans ce repo — c'est ce qui ferme la boucle et rend la remédiation *automatique*.

> **Pourquoi self-hosted (et pas Mend SaaS / Dependabot / argocd-image-updater ?)**
> - **Mend SaaS / Dependabot** : hébergés chez GitHub → n'atteignent pas le Harbor **interne** `registry-dev.soma-smart.cloud` → ne peuvent pas résoudre le digest des golden bases. (Mend marche sur Outline seulement parce que le `FROM` y pointe vers un registre *public*.)
> - **argocd-image-updater / Flux** : swappent l'image *déployée*, ne **rebuildent** pas une app depuis une base fraîche. Or base→rebuild passe forcément par un bump du `FROM` + CI.
> - **Renovate self-hosted** tourne sur le runner interne (atteint Harbor), résout le digest privé via `hostRules`, ouvre une PR et l'automerge. C'est l'outil unique de gestion des deps sur toutes les apps (base DHI **+** pip **+** github-actions).

### Composants

| Élément | Rôle |
|---|---|
| `.github/workflows/renovate.yml` | Lance Renovate self-hosted (cron 3×/jour + `workflow_dispatch`) sur le runner `onprem-dev-base-images`. Génère un token d'installation de la GitHub App puis exécute `renovatebot/github-action`. |
| `renovate-config.js` | **Config globale unique** (`requireConfig: "ignored"` → les `renovate.json` de repo sont ignorés). `autodiscover` + `hostRules` Harbor + `packageRules` (voir plus bas). |
| GitHub App **`soma-base-bumper`** | Auth de Renovate. `autodiscover` ⇒ **son installation = la liste des repos consommateurs**. Perms : `contents:write` + `pull-requests:write` + `checks:read` + `statuses:read`. Secrets repo : `BASE_BUMPER_APP_ID`, `BASE_BUMPER_PRIVATE_KEY`. |
| `ci-docker-build.yml` (dans **chaque app**) | Gate : `docker build` sur PR. C'est le check qui doit passer au vert avant que Renovate automerge un bump de digest. |

### Le flux

```
mirror-dhi (02:00)  ──▶  base/python:<ver> redigesté (Harbor privé)
                                   │  nouveau digest
renovate.yml (cron/dispatch)       ▼
  autodiscover (App soma-base-bumper) → hostRules résout le digest sur Harbor
  ouvre une PR "Update …/base/python:<ver> digest to <court>"  sur l'app
        │
  ci-docker-build (PR) builde l'app sur la base candidate  ──▶  vert
        │
  Renovate automerge (org Free : merge côté Renovate quand les checks sont verts)
        │  merge sur main de l'app
  CD continu de l'app (push main) rebuild → bump image.tag dans infra-datacenter-docs → ArgoCD
```

### `packageRules` (résumé)

| Famille | Comportement |
|---|---|
| `…/base/python` (digest interne) | **automerge** digest/pin (gate = `ci-docker-build`). ⚠️ La règle `pinDigests` est **séparée** de la règle `automerge` : `pinDigests` derrière un `matchUpdateTypes` **ne génère pas** le pin (piège Renovate). |
| `python` (builder slim public) | `enabled: false` — stage jeté, CVE non shippées, volontairement non suivi. |
| `github-actions` | automerge minor/patch/digest (SHA-pinnées) ; **majors** → Dependency Dashboard. |
| `pip` / `pep621` | **PR, revue humaine** (pas d'automerge). |

`prHourlyLimit: 0` : le bump de digest de base n'est jamais rate-limité.

### Ajouter une app à la boucle

1. Installer la GitHub App **`soma-base-bumper`** sur le repo de l'app (action org-admin).
2. Rebaser son `Dockerfile` sur `registry-dev.soma-smart.cloud/base/python:<ver>@sha256:<digest>` (runtime **digest-pinné littéral**).
3. Ajouter `.github/workflows/ci-docker-build.yml` (gate build sur PR, runner interne).
4. C'est tout — pas de `renovate.json` par repo (la config globale gère). Renovate découvrira l'app au run suivant.

### Exemple concret — E2E validé le 2026-07-06 (agent-infogerance)

Déroulé réel, de bout en bout, **sans aucune action manuelle** entre l'étape 2 et 6 :

1. **État initial** — `agent-infogerance/Dockerfile` runtime pinné :
   `FROM registry-dev.soma-smart.cloud/base/python:3.14@sha256:691eb62d…`
2. **Simulation d'un mouvement de base** — on retire le digest (`FROM …/base/python:3.14`) et on pousse sur `main`.
3. **Renovate détecte** — le run `renovate.yml` résout le digest courant sur le Harbor privé et ouvre **PR #35** : *« chore(deps): pin registry-dev.soma-smart.cloud/base/python docker tag to 691eb62 »*
   ```diff
   -FROM registry-dev.soma-smart.cloud/base/python:3.14
   +FROM registry-dev.soma-smart.cloud/base/python:3.14@sha256:691eb62d78825b1eb…
   ```
4. **Gate** — `ci-docker-build` builde l'app sur la base pinnée → **vert** (+ `quality`, `secrets` verts).
5. **Automerge** — au run Renovate suivant, checks verts constatés → **Renovate merge #35 lui-même** (org Free, `platformAutomerge: false`).
6. **Rebuild + deploy** — le merge sur `main` déclenche le CD continu → build `20260706-094934-23ae92f` → PR de bump `image.tag` (#531) auto-mergée dans `infra-datacenter-docs` → **ArgoCD** déploie → pod `agent-infogerance-5fcbcb849b-wlbkj` **Running**.

En production, l'étape 2 n'est pas simulée : c'est le `mirror-dhi` nocturne qui redigeste la base ; le reste est identique.

### Pièges opérationnels

- **`pinDigests` doit être dans sa propre règle** (sans `matchUpdateTypes`) — sinon une base non-pinnée n'est jamais pinnée.
- **Auth Harbor silencieuse** : si `HARBOR_USERNAME`/`HARBOR_PASSWORD` sont faux/expirés, la résolution du digest échoue **en warning** (job vert, aucune PR). Le **Dependency Dashboard** (`dependencyDashboard: true`) surface ces « Dependency Lookup Warnings » — les surveiller.
- **Org GitHub Free** : pas de branch protection → `platformAutomerge: false` (Renovate merge lui-même après avoir constaté les checks verts). Le gate `ci-docker-build` de l'app est donc le **seul** vrai filet ⇒ chaque app dans la boucle **doit** l'avoir.
- **Un check rouge sans rapport bloque l'automerge** : Renovate attend **tous** les checks verts. Ex. constaté sur som-portal (check `pip-audit` rouge à cause de CVE applicatives) → l'automerge d'un bump de digest ne part pas tant que ces CVE ne sont pas corrigées (ce que Renovate propose par ailleurs via ses PR pip).

## Contexte

Spec & plan : `soma-smart/infra-datacenter-docs` → `docs/superpowers/{specs,plans}/` :
- `2026-07-03-industrialisation-cve-harbor*` — le socle (mirror DHI + projet Harbor `base`).
- `2026-07-06-boucle-remediation-cve-renovate-design.md` — la boucle Renovate self-hosted (cette section).

Ticket : [OpenProject #3793](https://projet.soma-smart.cloud/work_packages/3793).
