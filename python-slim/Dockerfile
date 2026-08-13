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

# pip est RETIRÉ de ce socle d'exécution, et l'invariant est STRUCTUREL, pas lié à
# une CVE du moment : **pip embarque ses propres dépendances** (`pip/_vendor`), donc
# un socle qui porte pip porte en permanence les CVE de ce qu'il vendore — et aucune
# commande à l'intérieur de l'image ne peut les corriger, un `pip install --upgrade`
# posant une SECONDE copie dans site-packages et laissant `_vendor` intact. Le seul
# geste qui les supprime est celui-ci. (L'occurrence qui a motivé le retrait, avec
# ses numéros et ses dates, est dans le commit et dans #3913 — pas ici, où elle
# rotterait et ferait croire que la raison a disparu une fois ces CVE corrigées.)
#
# ⚠️ PRÉREQUIS, et rien ne le garantit mécaniquement : aucun consommateur de ce socle
# ne doit invoquer pip à l'EXÉCUTION — tous doivent résoudre leurs dépendances en
# stage *builder* puis `COPY --from`. Vérifié dépôt par dépôt le 2026-08-13. À
# revérifier avant tout changement ici, par balayage `^FROM.*base/python-slim` de
# l'org — en lisant le STAGE où vit le `pip install`, pas sa seule présence : un
# builder et un runtime produisent la même ligne et ont des sens opposés.
#
# ⚠️ Conséquence à connaître : `python -m venv` ne fonctionne plus dans les images
# dérivées (« ensurepip is not available »), sauf `--without-pip`.
#
# ⚠️ `ensurepip` doit partir AUSSI, sinon le retrait est cosmétique : il embarque une
# roue pip COMPLÈTE, donc les mêmes copies vendorées, et `python -m ensurepip` les
# restaure. ⚠️ Et Trivy ne les y voit PAS — son analyseur `python-pkg` lit les
# `.dist-info`, pas l'intérieur d'un `.whl` (mesuré : sur l'image amont il énumère
# 19 paquets python et un SEUL porte un chemin, celui de pip ; si la roue embarquée
# était ouverte, msgpack apparaîtrait deux fois puisqu'elle est de la même version).
# C'est précisément ce qui rend le laisser dangereux : le gate resterait VERT.
#
# ⚠️ Les trois assertions finales ne sont pas du zèle, et il en faut trois. Un
# `rm -rf` dont le glob ne matche rien réussit en silence : si une disposition amont
# change (préfixe, mineure), les `rm` deviennent des no-op tandis que le
# `pip uninstall` — qui, lui, n'est pas un glob — réussit quand même. Sans
# l'assertion `ensurepip`, ce cas passerait au VERT en laissant la roue en place,
# c'est-à-dire exactement la panne muette que ce bloc existe pour supprimer.
RUN python -m pip uninstall --yes pip \
 && rm -rf /usr/local/lib/python*/ensurepip \
           /usr/local/lib/python*/site-packages/pip* \
           /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.* \
 && ! command -v pip \
 && ! python -c "import pip" \
 && ! python -c "import ensurepip"

ENV HOME=/home/nonroot \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUTF8=1

WORKDIR /app
USER 65532
