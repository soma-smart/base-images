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
- **Gate Trivy** : avant push, `trivy image --ignore-unfixed --severity CRITICAL,HIGH --exit-code 1` échoue si une CVE fixable Critical/High subsiste → on ne propage jamais une base régressée.
- **Versions maintenues** : `3.11`, `3.12`, `3.13`, `3.14` (union des versions utilisées par les apps).

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

Une fois les deux prérequis en place, **décommenter le bloc `schedule`** dans le workflow.

## Contexte

Spec & plan : `soma-smart/infra-datacenter-docs` → `docs/superpowers/{specs,plans}/2026-07-03-industrialisation-cve-harbor*`. Ticket : [OpenProject #3793](https://projet.soma-smart.cloud/work_packages/3793).
