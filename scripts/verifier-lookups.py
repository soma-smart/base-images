#!/usr/bin/env python3
"""Fait ECHOUER le run Renovate si une resolution de dependance n'a pas abouti.

⚠️ POURQUOI CE SCRIPT EXISTE. Quand un lookup echoue, Renovate n'ouvre aucune PR et
ecrit un avertissement dans le CORPS de la Dependency Dashboard. Le job reste VERT.
L'epingle concernee gele alors exactement comme si personne ne la suivait, et c'est
indiscernable de « rien a mettre a jour ».

Mesure : `aquasecurity/trivy` a echoue a CHAQUE run pendant des semaines — l'amont a
active une IP allow list GitHub, qui rejette nos requetes AUTHENTIFIEES. Le scanner de
CVE de tout le parc est reste fige sans qu'aucun signal ne parte.

⚠️ CE QUE CE GATE NE VOIT PAS, et qui gele tout autant. Son vert signifie « aucune
resolution n'a echoue », JAMAIS « tout est suivi » :
  - `skipReason` (invalid-name, internal-package, ignored, disabled) : aucun warning,
    rien au-dessus de `debug`. Une dependance qui y bascule disparait sans un mot ;
  - un customManager qui ne matche RIEN : inerte, zero erreur — seul observable, la
    section `custom.regex` du Dependency Dashboard (deja paye : six versions de multica) ;
  - un `packageFile` non parse : `debug` seulement ;
  - un abandon de depot (« Caught error setting branch status - aborting ») : le depot
    sort sans PR et sans avertissement de lookup ;
  - un `enabledManagers` ampute : le manager retire cesse d'extraire, silence total.

⚠️ COUPLAGE NON EVIDENT : le champ `warnings` n'est emis que par le chemin qui construit
la Dependency Dashboard. Retirer `dependencyDashboard: true` de `renovate-config.js`, ou
ajouter `dependencyLookupWarnings` a `suppressNotifications`, rend ce gate AVEUGLE sans
le rendre rouge. Un commentaire croise est pose la-bas ; ne pas le retirer.
"""
import json
import sys

# ⚠️ QUATRE FAMILLES, pas une. `lookupUpdates` pousse quatre formes distinctes dans le
# MEME tableau `warnings` (verifie dans l'image renovate:43). N'en garder qu'une laisse
# passer les trois autres — et « Could not determine new digest » est precisement celle
# qui frapperait le digest du socle DHI, la dependance n°1 de cette config : un hostRule
# Harbor qui n'authentifie plus produit ce warning-la, et rien d'autre.
MOTIFS = (
    "Failed to look up",
    "Could not determine new digest",
    "Can't find version",
)


def analyser(chemin):
    """Rend (entrees, malformees, depots_termines, avertissements)."""
    entrees = 0
    malformees = 0
    depots = set()
    trouves = []
    with open(chemin, encoding="utf-8", errors="replace") as journal:
        for ligne in journal:
            ligne = ligne.strip()
            if not ligne:
                continue
            if not ligne.startswith("{"):
                # Renovate ecrit une entree JSON par ligne. Une ligne qui ne commence
                # pas par `{` n'est pas une entree tronquee : c'est du bruit (banniere,
                # sortie d'un autre outil). On l'ignore sans la compter comme malformee.
                continue
            try:
                entree = json.loads(ligne)
            except ValueError:
                # ⚠️ COMPTEE, JAMAIS AVALEE. Une ligne JSON tronquee est la fin du
                # fichier neuf fois sur dix — or `Package lookup failures` est emis TARD
                # dans le traitement d'un depot. La troncature frappe donc justement
                # l'entree qu'on cherche. Un `continue` nu rendait vert sur ce cas.
                malformees += 1
                continue
            entrees += 1
            if "Repository finished" in str(entree.get("msg", "")):
                depots.add(str(entree.get("repository", "?")))
            for avertissement in entree.get("warnings") or []:
                # `warnings` porte des chaines OU des objets selon le chemin de code :
                # supposer la chaine laisserait passer l'objet, sans un mot.
                texte = (avertissement if isinstance(avertissement, str)
                         else json.dumps(avertissement, ensure_ascii=False))
                if any(m in texte for m in MOTIFS) and texte not in trouves:
                    trouves.append(texte)
    return entrees, malformees, depots, trouves


def main(argv):
    if len(argv) != 2:
        print("usage: verifier-lookups.py <journal.ndjson>")
        return 2
    chemin = argv[1]
    try:
        entrees, malformees, depots, trouves = analyser(chemin)
    except OSError as erreur:
        print(f"::error::journal Renovate illisible ({chemin}) : {erreur}")
        print("        Ne pas lire ca comme « aucun echec » : le gate n'a rien pu prouver.")
        return 1

    # ⚠️ TROIS GARDES POSITIFS, DANS CET ORDRE. Chacun ferme un chemin par lequel le
    # gate rendrait VERT sans avoir rien examine — c'est-a-dire reproduirait, dans le
    # gate lui-meme, la panne qu'il existe pour supprimer.
    if entrees == 0:
        print(f"::error::journal illisible ou vide ({chemin}) : 0 entree JSON.")
        print("        Le gate n'a RIEN examine — ce n'est pas « aucun echec ».")
        return 1
    if malformees:
        print(f"::error::{malformees} ligne(s) JSON illisible(s) dans {chemin} — journal tronque.")
        print("        Le gate ne peut pas conclure : l'avertissement cherche est emis")
        print("        TARD dans un depot, donc c'est la fin du fichier qui manque.")
        return 1
    if not depots:
        # ⚠️ « Des entrees ont ete lues » ne prouve PAS qu'un depot a ete traite. Si
        # l'App perd une installation, `autodiscover` rend 0 depot : Renovate journalise
        # proprement, sort 0, aucune PR — indiscernable de « rien a mettre a jour ».
        print(f"::error::aucun depot termine dans {chemin} — Renovate n'a traite AUCUN depot.")
        print("        Causes typiques : installation de la GitHub App retiree,")
        print("        autodiscover vide, abandon precoce. Ce n'est pas « aucun echec ».")
        return 1

    if trouves:
        for texte in trouves:
            print(f"::error::resolution en echec : {texte}")
        print("")
        print("Une dependance dont la resolution echoue N'EST PLUS SUIVIE : aucune PR ne")
        print("sera ouverte, et rien d'autre que ce gate ne le dira.")
        return 1

    print(f"aucune resolution en echec ({entrees} entrees, {len(depots)} depot(s) traite(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
