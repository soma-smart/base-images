#!/usr/bin/env bash
# Installe Trivy depuis la release GitHub épinglée dans `.trivy-version` — UNE seule source de version,
# partagée par `build-python-slim.yml`, `copie-alpine.yml` et `mirror-dhi.yml`.
#
# Testé par `scripts/test_install_trivy.py` (chemin nominal ET modes d'échec).
#
# ⚠️ POURQUOI UN SCRIPT, ET POURQUOI UN FICHIER DE VERSION HORS DES WORKFLOWS.
#   - Trois blocs recopiés dans trois workflows : un bump devait les garder alignés à la main.
#   - La version vit dans `.trivy-version`, PAS dans un `env:` de workflow : le `GITHUB_TOKEN` d'un workflow ne
#     peut jamais modifier un fichier sous `.github/workflows/`. Le workflow `bump-trivy.yml` n'aurait donc pas pu
#     ouvrir sa PR sans un PAT à droit `workflow` — un secret capable de réécrire n'importe quel workflow de ce
#     dépôt, qui tourne sur des runners portant les identifiants Harbor.
#
# ⚠️ POURQUOI `--retry-all-errors`. Un `--retry` seul ne rejoue que les erreurs « transitoires » (timeout, HTTP 408,
#   429, 5xx) : ni un échec de résolution DNS (exit 6), ni une connexion refusée. Le build du 2026-11-04 est tombé
#   sur une panne DNS passagère. `-S` : sans lui, curl n'imprime pas la raison et le log se réduit à « exit code 6 ».
#
# ⚠️ Le SHA-256 vient du fichier de sommes de la MÊME release (même hébergeur que l'archive) : il protège contre une
#   archive tronquée ou corrompue, PAS contre une release compromise. Même niveau que l'ancien `install.sh`.
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(tr -d '[:space:]' < "$racine/.trivy-version")"

# La valeur finit dans une URL : on n'accepte que X.Y.Z (ni `v` initial, ni suffixe, ni vide).
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "ERREUR: .trivy-version doit contenir X.Y.Z (reçu : '${version}')" >&2
  exit 1
fi

dest="$HOME/.local/bin"
base="https://github.com/aquasecurity/trivy/releases/download/v${version}"
archive="trivy_${version}_Linux-64bit.tar.gz"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$dest"
curl -fsSL --retry 3 --retry-all-errors --retry-delay 5 -o "$tmp/$archive" "$base/$archive"
curl -fsSL --retry 3 --retry-all-errors --retry-delay 5 -o "$tmp/checksums.txt" "$base/trivy_${version}_checksums.txt"
# `pipefail` : une ligne de somme ABSENTE (grep sans résultat) fait échouer le step, elle ne passe pas pour « vérifié ».
(cd "$tmp" && grep -F " $archive" checksums.txt | sha256sum -c -)
tar -xzf "$tmp/$archive" -C "$dest" trivy

# `GITHUB_PATH` ne vaut qu'à partir du step SUIVANT : on appelle le binaire par son chemin pour l'afficher ici.
if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$dest" >> "$GITHUB_PATH"
fi
"$dest/trivy" --version
