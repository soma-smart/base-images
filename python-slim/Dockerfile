# syntax=docker/dockerfile:1
# Base SLIM durcie partagée (gabarit Soma) — pour les apps Python scientifiques
# (pandas/scipy/scikit-learn) que le socle DHI *distroless* ne couvre pas : elles ont
# besoin d'un runtime glibc complet (libstdc++, libgomp) que le distroless n'offre pas.
#
# Non-distroless (shell/apt présents) MAIS durcie : non-root uid 65532 (aligné sur le
# socle DHI), libgomp1 (runtime OpenMP pour scipy/scikit-learn — les wheels le vendorent
# souvent, on le fournit en filet de sécurité), UTF-8 forcé, pas de cache apt.
#
# Tag `base/python-slim:<ver>` VOLONTAIREMENT mouvant : rebuild nocturne depuis le
# dernier `python:<ver>-slim` (patchs Debian) → redigesté. Les consommateurs épinglent
# par digest via Renovate (comme base/python). Trivy-gaté au build.
ARG PY_VERSION=3.14
FROM python:${PY_VERSION}-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends libgomp1 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 65532 nonroot \
 && useradd --uid 65532 --gid 65532 --create-home --home-dir /home/nonroot nonroot

ENV HOME=/home/nonroot \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUTF8=1

WORKDIR /app
USER 65532
