# Source AMONT de la copie `ghcr.io/soma-smart/base/alpine` (workflow `copie-alpine.yml`). Ce Dockerfile ne CONSTRUIT RIEN : il
# porte la version ET le digest en un seul endroit lisible par un manager `dockerfile`. Le workflow lit cette unique ligne FROM,
# scanne CE digest (Trivy), puis copie CE digest vers ghcr — jamais un tag résolu une seconde fois.
# ⚠️ BUMP MANUEL aujourd'hui : `base-images` n'est pas dans le périmètre de Renovate (constaté le 2026-10-19 : 8 dépôts
# autodécouverts, ni celui-ci ni `mcp-servers`). L'alarme est le cron nocturne de `copie-alpine.yml`, qui devient ROUGE à la
# première CVE corrigeable ou à la fin de support ; au bump, vérifier à la main que la version a ≥ 3 jours. Image du conteneur de job des builds MCP (`mcp-servers`), où tourne du code d'auteur non relu :
# une branche Alpine HORS SUPPORT n'y reçoit plus aucun correctif (la 3.20 est sortie de support le 2026-04-01).
# ⚠️ Une seule ligne FROM, sans `AS` : le workflow refuse tout autre forme.
FROM docker.io/library/alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
