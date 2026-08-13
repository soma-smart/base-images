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

# pip est RETIRÉ de ce socle. Ce n'est pas une économie de taille, c'est ce qui rend
# le gate Trivy tenable : pip EMBARQUE ses dépendances dans `pip/_vendor`, et le
# `vendor.txt` de pip 26.2.1 y épingle `msgpack==1.1.2` et `setuptools==70.3.0` —
# deux CVE HIGH *corrigeables*, donc bloquantes, et qu'aucun geste dans l'image ne
# corrige : un `pip install --upgrade setuptools` pose une SECONDE copie dans
# site-packages et laisse `_vendor` intact. Le gate a été rouge 8 nuits pour ça
# (2026-08-06 → 2026-08-13), sans que rien ne le signale.
#
# Aucun consommateur n'y perd : les trois (dev-finops-app, multica-runtime et le
# gabarit soma-app-template) résolvent leurs dépendances en stage *builder* puis
# copient — vérifié par balayage des 154 dépôts non archivés de l'org.
#
# ⚠️ `ensurepip` doit partir AUSSI, sinon le retrait est cosmétique : il embarque une
# roue pip complète — donc les mêmes copies vendorées, que Trivy voit — et un simple
# `python -m ensurepip` réinstallerait le tout.
#
# ⚠️ Les deux dernières lignes sont des ASSERTIONS, pas du zèle. Un `rm -rf` dont le
# glob ne matche rien réussit en silence : sans elles, un changement de disposition
# amont (chemin de site-packages, version mineure) laisserait pip en place et le
# socle repartirait vulnérable, vert au build et rouge seulement au gate — c'est-à-dire
# diagnostiqué comme « encore une CVE amont » plutôt que comme un retrait qui a raté.
RUN python -m pip uninstall --yes pip \
 && rm -rf /usr/local/lib/python*/ensurepip \
           /usr/local/lib/python*/site-packages/pip* \
           /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.* \
 && ! command -v pip \
 && ! python -c "import pip"

ENV HOME=/home/nonroot \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUTF8=1

WORKDIR /app
USER 65532
