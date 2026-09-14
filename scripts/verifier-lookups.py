#!/usr/bin/env python3
"""Fait ECHOUER le run Renovate si une datasource n'a pas resolu.

⚠️ POURQUOI CE SCRIPT EXISTE. Quand un lookup echoue, Renovate n'ouvre aucune PR et
ecrit un avertissement dans le CORPS de la Dependency Dashboard. Le job reste VERT.
L'epingle concernee gele alors exactement comme si personne ne la suivait, et c'est
indiscernable de « rien a mettre a jour ».

Mesure : `aquasecurity/trivy` a echoue a CHAQUE run pendant des semaines — l'amont a
active une IP allow list GitHub, qui rejette nos requetes AUTHENTIFIEES. Le scanner de
CVE de tout le parc est reste fige sans qu'aucun signal ne parte.

⚠️ ON LIT LE JOURNAL NDJSON, PAS LA SORTIE CONSOLE. Celle-ci porte des sequences ANSI
(`\x1b[35m WARN\x1b[39m`) qui font rater un motif — en silence, donc de la pire facon.

⚠️ UN JOURNAL ABSENT OU ILLISIBLE EST UN ECHEC, jamais un succes. Un gate qui ne peut
rien prouver ne doit pas rendre vert : c'est une absence de signal, pas un feu vert.
"""
import json
import sys

MOTIF = "Failed to look up"


def echecs_de_lookup(chemin):
    """Rend (nb_entrees_lues, avertissements) — le premier sert a prouver qu'on a LU."""
    vus = []
    entrees = 0
    with open(chemin, encoding="utf-8", errors="replace") as journal:
        for ligne in journal:
            ligne = ligne.strip()
            # Renovate ecrit une entree JSON par ligne ; tout le reste est ignore.
            if not ligne.startswith("{"):
                continue
            try:
                entree = json.loads(ligne)
            except ValueError:
                continue
            entrees += 1
            # ⚠️ `warnings` peut porter des chaines OU des objets selon le chemin de
            # code. On serialise plutot que de supposer, sinon un objet passerait au
            # travers du test de sous-chaine sans que rien ne le signale.
            for avertissement in entree.get("warnings") or []:
                texte = (avertissement if isinstance(avertissement, str)
                         else json.dumps(avertissement, ensure_ascii=False))
                if MOTIF in texte and texte not in vus:
                    vus.append(texte)
    return entrees, vus


def main(argv):
    if len(argv) != 2:
        print("usage: verifier-lookups.py <journal.ndjson>", file=sys.stderr)
        return 2
    chemin = argv[1]
    try:
        entrees, trouves = echecs_de_lookup(chemin)
    except OSError as erreur:
        print(f"::error::journal Renovate illisible ({chemin}) : {erreur}", file=sys.stderr)
        print("        Ne pas lire ca comme « aucun echec » : le gate n'a rien pu prouver.",
              file=sys.stderr)
        return 1
    # ⚠️ ZERO ENTREE LUE = ECHEC, et c'est le garde le plus important du script. Un
    # fichier present mais illisible (mauvais format, journal console au lieu du
    # NDJSON, troncature) ne contient aucun avertissement — donc le test ci-dessous
    # passerait au VERT en n'ayant rien examine. C'est exactement la panne que ce gate
    # existe pour supprimer, reproduite dans le gate lui-meme.
    if entrees == 0:
        print(f"::error::journal Renovate illisible ou vide ({chemin}) : 0 entree JSON lue.")
        print("        Le gate n'a RIEN pu examiner — ce n'est pas « aucun echec ».",
              file=sys.stderr)
        return 1
    if trouves:
        for texte in trouves:
            print(f"::error::lookup en echec : {texte}")
        print("", file=sys.stderr)
        print("Une dependance dont le lookup echoue N'EST PLUS SUIVIE : aucune PR ne sera",
              file=sys.stderr)
        print("ouverte, et rien d'autre que ce gate ne le dira.", file=sys.stderr)
        return 1
    print(f"aucun echec de lookup sur ce run ({entrees} entrees examinees)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
