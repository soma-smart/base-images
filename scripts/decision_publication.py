#!/usr/bin/env python3
"""Décide si le socle python-slim construit doit être publié, ou si l'image déjà publiée suffit.

Le rebuild nocturne ne donne jamais deux fois le même digest (horodatages dans les traces apt/dpkg, `shadow`,
cache ldconfig) : sans cette décision, chaque nuit republie un digest neuf, correctif Debian ou non.

On PUBLIE si l'une de ces conditions est vraie, et l'on SAUTE seulement si TOUTES sont fausses :
  1. aucune image publiée (tag absent) ;
  2. l'inventaire `dpkg` diffère de celui de l'image publiée ;
  3. la base `python:<ver>-slim` a changé — jugé sur les COUCHES, pas sur les paquets : Python vit dans
     /usr/local, invisible de dpkg. Les couches de la base doivent être un PRÉFIXE de celles de l'image publiée ;
  4. les sources du socle (arbre git de `python-slim/`) diffèrent du label de l'image publiée — ou le label manque.

⚠️ L'image publiée est lue PAR DIGEST, jamais par son tag : le tag désigne, sur le runner, la construction locale
si on la nomme ainsi, et l'on comparerait alors la construction à elle-même (« inchangé » à vie, job vert, plus
aucune publication). Le candidat porte donc un nom local distinct.

⚠️ Tout cas inconnu penche vers la PUBLICATION, sauf une lecture impossible : une erreur d'authentification ou de
réseau, un inventaire vide ou sans `libc6` font ÉCHOUER le job (jamais « inchangé » par défaut).

Usage : decision_publication.py <candidat local> <repo:tag publié> <base python:<ver>-slim> <arbre des sources>
Écrit `publier`, `raison`, `digest` dans $GITHUB_OUTPUT (digest = celui de l'image publiée, vide si absente).
"""
import json
import os
import re
import subprocess
import sys

DELAI_S = 600
LABEL_SOURCES = "cloud.soma-smart.python-slim.source-tree"
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}\Z")
ARBRE = re.compile(r"^[0-9a-f]{40}\Z")
ABSENT = ("MANIFEST_UNKNOWN", "NAME_UNKNOWN")


class DecisionError(RuntimeError):
    pass


def _exec(run, argv):
    try:
        r = run(argv, capture_output=True, text=True, timeout=DELAI_S)
    except FileNotFoundError:
        raise DecisionError(f"{argv[0]} est introuvable dans le PATH") from None
    except subprocess.TimeoutExpired:
        raise DecisionError(f"delai de {DELAI_S}s depasse : {' '.join(argv)}") from None
    return r


def _ok(run, argv):
    r = _exec(run, argv)
    if r.returncode != 0:
        raise DecisionError(f"{' '.join(argv)} a échoué (code {r.returncode}) : {(r.stderr or '').strip()}")
    return (r.stdout or "").strip()


def digest_publie(run, ref):
    """Digest du tag publié, ou None s'il n'existe pas. Toute autre erreur (auth, réseau) lève."""
    r = _exec(run, ["crane", "digest", ref])
    if r.returncode != 0:
        if any(m in (r.stderr or "") for m in ABSENT):
            return None
        raise DecisionError(f"crane digest {ref} a échoué (code {r.returncode}) : {(r.stderr or '').strip()}")
    d = (r.stdout or "").strip()
    if not DIGEST.match(d):
        raise DecisionError(f"digest publié illisible pour {ref} : {d!r}")
    return d


def inventaire(run, image):
    sortie = _ok(run, ["docker", "run", "--rm", "--entrypoint", "dpkg-query", image,
                       "-W", "-f", "${Package}\t${Version}\t${Architecture}\n"])
    lignes = sorted(l for l in sortie.splitlines() if l.strip())
    if not any(l.split("\t")[0] == "libc6" for l in lignes):
        raise DecisionError(f"inventaire dpkg vide ou sans libc6 pour {image} ({len(lignes)} lignes) : lecture non fiable")
    return lignes


def _inspect(run, image, gabarit):
    return json.loads(_ok(run, ["docker", "image", "inspect", "--format", gabarit, image]))


def couches(run, image):
    c = _inspect(run, image, "{{json .RootFS.Layers}}")
    if not c:
        raise DecisionError(f"aucune couche lue pour {image}")
    return c


def label_sources(run, image):
    return (_inspect(run, image, "{{json .Config.Labels}}") or {}).get(LABEL_SOURCES)


def decider(run, candidat, ref, base, arbre):
    """(publier, raison, digest publié ou None)."""
    digest = digest_publie(run, ref)
    if digest is None:
        return True, "aucune image publiée sous ce tag", None
    publiee = f"{ref.rpartition(':')[0]}@{digest}"
    _ok(run, ["docker", "pull", "--quiet", publiee])
    inv_nouveau, inv_publie = inventaire(run, candidat), inventaire(run, publiee)
    if inv_nouveau != inv_publie:
        diff = sorted(set(inv_nouveau) ^ set(inv_publie))
        return True, f"inventaire dpkg différent ({len(diff)} lignes, ex. {diff[0].split(chr(9))[0]})", digest
    base_c, publiee_c = couches(run, base), couches(run, publiee)
    # La base lue doit être CELLE du candidat : un tag mouvant relu après coup (ou un tag local périmé) ferait comparer
    # le publié à une base que le candidat ne contient pas — et un vrai changement de base passerait pour « inchangé ».
    if couches(run, candidat)[:len(base_c)] != base_c:
        raise DecisionError(f"le candidat n'est pas construit sur les couches lues de {base} (tag déplacé entre le build et la décision, ou tag local périmé)")
    if publiee_c[:len(base_c)] != base_c:
        return True, "la base python:<ver>-slim a changé (couches)", digest
    pub = label_sources(run, publiee)
    # Le label vient d'un objet mutable : une valeur qui n'a pas la forme d'un arbre git est traitée comme ABSENTE
    # (publier), et n'est jamais recopiée dans les sorties.
    if not (isinstance(pub, str) and ARBRE.match(pub)) or pub != arbre:
        return True, "sources du socle différentes ou label absent/illisible", digest
    return False, "inventaire, base et sources inchangés", digest


def ecrire(sortie, publier, raison, digest):
    raison = " ".join(raison.split())[:200]  # une valeur lue d'un registre ne doit pas pouvoir ajouter de lignes à $GITHUB_OUTPUT
    ligne = f"publier={'true' if publier else 'false'}\nraison={raison}\ndigest={digest or ''}\n"
    print(ligne, end="")
    if sortie:
        with open(sortie, "a") as f:
            f.write(ligne)


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    try:
        ecrire(os.environ.get("GITHUB_OUTPUT"), *decider(subprocess.run, *sys.argv[1:]))
    except DecisionError as e:
        sys.exit(f"ERREUR: {e}")
