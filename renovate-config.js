// Config GLOBAL et UNIQUE du Renovate self-hosted (boucle de remédiation CVE).
//
// Modèle homogène (2026-07-06) : UN SEUL outil de gestion des dépendances sur tous
// les repos d'apps — Renovate self-hosted. Plus de Dependabot, plus de renovate.json
// par repo. Ce fichier est la seule source de vérité (requireConfig: "ignored" =>
// les éventuels renovate.json résiduels des repos sont ignorés).
//
// Portée : autodiscover sur les repos où la GitHub App `soma-base-bumper` est
// installée (= les consommateurs). Quatre familles de mises à jour, uniformes partout :
//   1. digest de la base DHI interne  -> automerge (gate = ci-docker-build sur PR)
//   2. github-actions (SHA-pinnées)   -> automerge minor/patch/digest, majors en dashboard
//   3. deps applicatives (pip/pep621) -> mineur/patch automerge (matures 3j), majeur en PR
//   4. épingles regex (custom.regex)  -> JAMAIS d'automerge, majeurs en dashboard
//
// ⚠️ La famille 4 ne partage AUCUNE `packageRule` avec les trois autres : elles
// gatent toutes sur `matchManagers`, et un dep extrait par un manager regex se
// déclare `custom.regex`. Sans sa propre règle, elle n'hériterait donc de rien —
// ni maturation supply-chain, ni revue des majeurs — ce qui serait l'inverse de la
// politique de toutes les autres. Sa règle est écrite explicitement plus bas.
module.exports = {
  platform: "github",
  autodiscover: true,
  onboarding: false,
  // Ce fichier global est la SEULE config : on ignore tout renovate.json de repo
  // (sinon il serait mergé avec la précédence la plus haute et pourrait désactiver
  //  silencieusement la boucle — cf. review PR #1).
  requireConfig: "ignored",
  // ⚠️ CE N'EST PAS UN CONFORT, C'EST LA RÉPARATION D'UN GEL — trouvé en revue de
  // #14 (2026-09-14), même classe que l'incident déjà résolu dans
  // `infra-datacenter-docs/renovate.json` (#1368, PROJECT MEMORY
  // project_renovate_internalchecks_gel_sans_timestamp).
  //
  // Depuis Renovate 42, le défaut est `timestamp-required` : une release dont la
  // datasource n'expose AUCUN `releaseTimestamp` est réputée n'avoir jamais atteint
  // l'âge minimal — donc, combinée à `internalChecksFilter: "strict"` (posé plus bas
  // pour la famille 4), sa branche n'est JAMAIS créée. Ce n'est pas « en attente »,
  // c'est DÉFINITIF, et le Dependency Dashboard l'affiche en « Pending Status
  // Checks », indiscernable d'une vraie attente de 3 jours.
  //
  // La datasource `docker` sur un registre OCI générique (le `/v2/.../tags/list`
  // d'un proxy Harbor) ne rend AUCUN `releaseTimestamp` — contrairement à
  // `github-releases`. Le motif Trivy de ce fichier bascule précisément sur
  // `docker` en #14 : sans cette ligne, il aurait échangé un échec BRUYANT (gate
  // rouge sur lookup en échec) contre un gel SILENCIEUX (lookup réussi, release
  // filtrée en aval, gate vert, dep figé pour toujours) — l'inverse exact de ce que
  // #12/#13 existent pour garantir.
  //
  // ⚠️ Ça n'affaiblit AUCUNE protection réelle : là où le timestamp existe
  // (`github-releases`, `deb`), le seuil de 3 jours continue de s'appliquer. Là où
  // il n'existe pas, il ne protégeait rien — il bloquait.
  // ⚠️ L'observable existe et il est nouveau : sous `timestamp-optional`, Renovate
  // émet un `logger.once.warn` « Some release(s) did not have a releaseTimestamp …
  // proceeding », qui remonte dans « Repository Problems » du Dashboard. Il dit
  // QUE des releases contournent le gate d'âge, jamais lesquelles.
  // ⚠️ L'orthographe est BRITANNIQUE (`Behaviour`), et sa VALEUR n'est validée par
  // PERSONNE en amont — `renovate-config-validator` accepte n'importe quelle chaîne
  // sans un mot. Le gate de `validate-renovate-config.yml` la contrôle par un enum
  // explicite, pour que ce correctif ne devienne pas lui-même une épingle muette.
  minimumReleaseAgeBehaviour: "timestamp-optional",
  // Dashboard actif : surface les "Dependency Lookup Warnings" (ex. échec d'auth
  // Harbor sur hostRules) qui, sinon, rendent la boucle muette sans erreur de job.
  // ⚠️ CETTE LIGNE ALIMENTE LE GATE `verifier-lookups.py`, et ce couplage n'est
  // devinable depuis aucun des deux fichiers. Le champ `warnings` — le seul signal
  // qu'une résolution a échoué — n'est émis QUE par le chemin qui construit la
  // Dependency Dashboard. La retirer, ou ajouter `dependencyLookupWarnings` à
  // `suppressNotifications`, rend le gate AVEUGLE sans le rendre rouge : il
  // continuerait de passer au vert en n'ayant plus rien à examiner.
  dependencyDashboard: true,
  // ⚠️ DÉSACTIVE l'écriture du statut de commit `renovate/stability-days`, et ce
  // n'est pas cosmétique : sans ça, la maturation `minimumReleaseAge` BLOQUE les
  // mises à jour au lieu de les retarder.
  //
  // Mécanique, mesurée le 2026-08-13 sur une passe en `debug` : dès qu'une
  // dépendance soumise à maturation obtient une branche, Renovate publie un statut
  // de commit pour la refléter. L'App `soma-base-bumper` a `statuses: READ` — le
  // POST est refusé (« Resource not accessible by integration »), Renovate
  // journalise « Caught error setting branch status - aborting » et **abandonne le
  // dépôt AVANT de créer la PR**. La branche existe, la PR jamais. Le job de la
  // passe reste **vert**, et l'absence de PR est indiscernable d'un « rien à mettre
  // à jour » : trois mises à jour dormaient ainsi (ruff, azure-identity, outline).
  //
  // ⚠️ Ceci ne désactive PAS la maturation : le contrôle interne continue de retenir
  // la PR jusqu'à l'âge requis. Seule la *publication du statut* disparaît — un
  // affichage, pas une garantie.
  // ⚠️ Alternative écartée : accorder `statuses: write` à l'App. Ça marcherait, mais
  // ça élargit les droits d'un bot pour produire un affichage. Si la permission est
  // accordée un jour pour une autre raison, cette ligne pourra sauter.
  statusCheckNames: {
    minimumReleaseAge: null,
  },
  // Le bump de digest de base ne doit jamais etre rate-limite (sinon un rebuild DHI
  // peut attendre des heures derriere d'autres PR). 0 = illimite.
  prHourlyLimit: 0,
  // Remediation CVE PROACTIVE : Renovate interroge osv.dev pour les deps figees de
  // chaque app et ouvre une PR de fix DES qu'une CVE est publiee contre une version
  // epinglee (CVE-triggered, pas seulement "rester courant"). Comble le trou du scan
  // reactif (pip-audit ne tournait qu'a la PR). Self-hosted -> OSV direct, pas besoin
  // de Dependabot (org Free / repos prives). Le fix repasse par les gates ci-python +
  // ci-docker-build de l'app. Complementaire du scan Trivy planifie de Harbor (images).
  osvVulnerabilityAlerts: true,
  vulnerabilityAlerts: {
    enabled: true,
    labels: ["security", "vulnerability"],
    // Un fix de CVE ne doit PAS attendre la maturation 3j des bumps normaux ni le
    // quota horaire -> traitement prompt. L'automerge suit la politique existante
    // (mineur/patch automerge ; majeur = revue humaine, cf. packageRules).
    minimumReleaseAge: null,
  },
  enabledManagers: [
    "dockerfile",
    "pip_requirements",
    "pep621",
    "github-actions",
    // ⚠️ `custom.regex` est INSÉPARABLE du bloc `customManagers` ci-dessous : l'un
    // sans l'autre est silencieusement inerte, dans les deux sens. Sans ce manager
    // activé, les motifs ne sont jamais lus ; sans motifs, l'activer ne fait rien.
    "custom.regex",
  ],
  // ═══════════════════════════════════════════════════════════════════════════
  // Managers regex — versions épinglées dans des endroits qu'AUCUN manager natif
  // ne sait lire (un `ARG` de Dockerfile, une variable de workflow).
  //
  // ⚠️ ILS SONT ICI, ET PAS DANS LES DÉPÔTS, PARCE QU'ILS N'Y SERVIRAIENT À RIEN.
  // `requireConfig: "ignored"` ci-dessus fait que le `renovate.json` d'un dépôt
  // consommateur n'est JAMAIS lu. Un customManager écrit là-bas donne l'illusion
  // du suivi : la config est valide, la CI la valide, et rien ne tourne dessus.
  // Constaté le 2026-08-11 — `multica-runtime` portait ces trois managers en
  // local depuis le 2026-08-04 ; `multica` a filé de 0.4.17 à 0.4.23 (six
  // versions) sans une seule PR, et le rattrapage a été manuel.
  // Preuve que le fichier de dépôt est bien ignoré, sans interprétation
  // possible : ce même dépôt a posé `pinDigests: false` à sa racine le 04/08 à
  // 16:12, et cette boucle a épinglé son digest le lendemain à 07:05.
  //
  // ⚠️ Portée : ces motifs s'appliquent à TOUS les dépôts autodécouverts. C'est
  // sans effet de bord — un `matchStrings` qui ne matche pas est inerte — et
  // vérifié au 2026-08-11 : seul `multica-runtime` porte ces trois épingles.
  // Ajouter un manager ici, ce n'est donc pas « configurer un dépôt », c'est
  // déclarer un MOTIF que d'autres dépôts peuvent adopter.
  //
  // ⚠️ MAIS L'ADOPTION A UN CONTRAT DE NOMMAGE, et son non-respect est SILENCIEUX.
  // `managerFilePatterns` est un regex ancré sur le chemin COMPLET relatif au
  // dépôt, pas un simple nom de fichier. Un `docker/Dockerfile` ou un workflow
  // nommé `ci.yml` ne matcherait pas un motif écrit pour la racine — sans erreur,
  // sans PR, exactement la panne que ce bloc existe pour supprimer. Les motifs
  // ci-dessous sont donc volontairement PERMISSIFS sur l'emplacement (Dockerfile
  // à n'importe quelle profondeur, n'importe quel workflow) et stricts sur le
  // contenu. Ce dépôt-ci est son propre contre-exemple : son Dockerfile est en
  // `python-slim/Dockerfile` et son workflow s'appelle `build-python-slim.yml`.
  // ═══════════════════════════════════════════════════════════════════════════
  customManagers: [
    {
      // ⚠️ Renovate ne sait PAS recalculer `MULTICA_SHA256`, épinglé juste sous
      // cet ARG. Ses PR partiront donc ROUGES, et c'est le comportement VOULU :
      // le Dockerfile de multica-runtime l'écrit — « échouer bruyamment vaut
      // mieux que faire confiance en silence ». Le hash se récupère par
      //   curl -fsSL .../releases/download/v<VER>/checksums.txt | grep ' multica_linux_amd64.tar.gz$'
      // Ne pas « réparer » ce rouge en retirant l'épingle du hash : c'est un
      // contrôle délibéré (une release GitHub est MUTABLE).
      description: "ARG MULTICA_VERSION (Dockerfile) — daemon multica",
      customType: "regex",
      managerFilePatterns: ["/(^|/)Dockerfile$/"],
      // ⚠️ Ancré comme celui de GH_VERSION plus bas, et pour la même raison mesurée :
      // un motif non ancré matche une ligne commentée. Défaut de famille, corrigé sur
      // les deux motifs d'un coup plutôt que sur celui qui a mordu.
      matchStrings: ["(?m)^\\s*ARG MULTICA_VERSION=(?<currentValue>[^\\s#]+)"],
      depNameTemplate: "multica-ai/multica",
      datasourceTemplate: "github-releases",
      extractVersionTemplate: "^v(?<version>.*)$",
    },
    {
      // Le paquet vient du dépôt apt d'Anthropic — ni Debian, ni un registre
      // docker. Le datasource `deb` sait lire son index `Packages`.
      // ⚠️ L'URL pointe le canal `stable`, DÉLIBÉRÉMENT : il retarde d'environ une
      // semaine sur `latest` et saute les releases à régression majeure. Ne pas
      // le basculer sur `latest` en croyant rattraper un retard — l'écart EST le
      // choix. Et la version porte un suffixe de révision Debian (`-1`) qui fait
      // partie du numéro : `versioning: deb` est requis pour l'ordonner.
      description: "ARG CLAUDE_CODE_VERSION (Dockerfile) — CLI Claude Code, canal apt stable",
      customType: "regex",
      managerFilePatterns: ["/(^|/)Dockerfile$/"],
      // ⚠️ Ancré, comme les trois autres motifs de ce bloc : non ancré, il matcherait
      // une ligne commentée. Cf. la mesure du 2026-09-14 sur GH_VERSION.
      matchStrings: ["(?m)^\\s*ARG CLAUDE_CODE_VERSION=(?<currentValue>[^\\s#]+)"],
      depNameTemplate: "claude-code",
      datasourceTemplate: "deb",
      versioningTemplate: "deb",
      registryUrlTemplate:
        "https://downloads.claude.ai/claude-code/apt/stable?suite=stable&components=main&binaryArch=amd64",
    },
    {
      // La version de Trivy vit dans un bloc `env:` de workflow, invisible au
      // manager `github-actions` (qui ne lit que les `uses:`). Sans ce motif, le
      // scanner gèle et cesse de détecter les CVE récentes — un gate qui rend
      // vert sans plus rien prouver.
      //
      // ⚠️ CE MOTIF SUIT L'IMAGE, PLUS LA RELEASE GITHUB, ET C'EST UNE CORRECTION DE
      // PANNE. Il visait `github-releases` sur `aquasecurity/trivy` et échouait à
      // CHAQUE run depuis des semaines : l'organisation amont a activé une IP allow
      // list GitHub, qui rejette nos requêtes AUTHENTIFIÉES (message de GitHub :
      // « the `aquasecurity` organization has an IP allow list enabled »). Le scanner
      // de CVE de tout le parc est resté figé sans qu'aucun signal ne parte.
      // ⚠️ Ni un PAT ni `GITHUB_COM_TOKEN` n'y changeraient rien : le filtre porte sur
      // l'IP, pas sur le jeton. Mesuré — la même requête ANONYME, depuis la même IP,
      // rend 200. Ne pas « réparer » ce motif en lui ajoutant un jeton.
      //
      // ⚠️ On suit désormais L'ARTEFACT RÉELLEMENT CONSOMMÉ : le workflow de build tire
      // `dockerhub-proxy/aquasec/trivy:${TRIVY_VERSION}`. Surveiller autre chose que ce
      // qu'on exécute rouvrirait un écart entre l'index et la réalité — et ça supprime
      // toute dépendance à la politique IP d'un tiers, qui peut rechanger sans préavis.
      //
      // ⚠️ Deux mesures ont décidé, à ne pas re-supposer :
      //   - le proxy Harbor expose la liste COMPLÈTE des tags amont (0.1.6 → 0.74.0),
      //     pas seulement ceux déjà en cache — c'était la crainte principale, et elle
      //     était infondée ;
      //   - le versioning `docker` rend `isCompatible=false` pour `0.74.0-amd64`,
      //     `-arm64` et `-s390x` face à `0.73.0` : aucune variante d'architecture ne
      //     peut être proposée. Ne pas ajouter d'`allowedVersions` « au cas où ».
      //
      // ⚠️ Le listing du proxy répond en ANONYME (vérifié) — ce qui est heureux, car
      // `HARBOR_USERNAME`/`HARBOR_PASSWORD` n'atteignent pas le conteneur (filtrés par
      // l'`env-regex` de l'action). Ce défaut est traité à part ; ce motif n'en dépend
      // pas, mais ne pas conclure de son bon fonctionnement que les credentials passent.
      //
      // ⚠️ Plus d'`extractVersion` : les tags de l'image sont nus (`0.74.0`), sans le
      // `v` des tags Git. En conserver un ferait que rien ne matcherait plus — et un
      // motif qui ne matche rien ne lève aucune erreur.
      description: "TRIVY_VERSION (workflow de build) — scanner d'images, suivi via le proxy Harbor",
      customType: "regex",
      managerFilePatterns: ["/^\\.github/workflows/.*\\.ya?ml$/"],
      // ⚠️ Ancré, même raison que les motifs Dockerfile de ce bloc : une ligne YAML
      // commentée (`# TRIVY_VERSION: 0.60.0`) matcherait sinon.
      matchStrings: ["(?m)^\\s*TRIVY_VERSION: *[\"']?(?<currentValue>[^\"'\\s]+)[\"']?"],
      depNameTemplate: "registry-dev.soma-smart.cloud/dockerhub-proxy/aquasec/trivy",
      datasourceTemplate: "docker",
    },
    {
      // ⚠️ CELUI-CI N'A PAS DE HASH JUMEAU, contrairement à `MULTICA_VERSION` juste
      // au-dessus — et il ne faut pas lui en chercher un. `gh` n'est pas téléchargé :
      // il est COMPILÉ dans le dépôt consommateur, par un module enveloppe
      // (`go mod init` + `go get <PAQUET>@<ver>` + `go build`) — et c'est la toolchain
      // Go qui vérifie contre `sum.golang.org`. Rien à recalculer à la main, donc.
      //
      // ⚠️ MAIS NE PAS EN CONCLURE QUE SES PR SERONT VERTES. Une première rédaction
      // l'écrivait, et c'était une mauvaise promesse : le stage de build porte trois
      // contrôles qui peuvent rendre un bump ROUGE — le gate Trivy (il a déjà refusé
      // CVE-2026-56864/56865 le 2026-09-14), le plancher `go get golang.org/x/mod`, et
      // l'assertion qui tue le build si ce plancher n'a pas pris effet. Un rouge ici
      // est un gate qui travaille, pas une panne de la boucle : il se lit dans le
      // `security-exceptions.json` du consommateur, jamais dans cette config.
      //
      // ⚠️ Le `/v2` du chemin Go est le suffixe de MAJEURE du module. Un bump vers
      // `3.0.0` rendrait le `go get` du consommateur invalide — build rouge, donc
      // auto-révélateur, et les majeurs passent de toute façon par le Dashboard.
      //
      // ⚠️ Une seule ligne `ARG GH_VERSION=` existe côté consommateur, déclarée AVANT
      // le premier FROM (portée globale) et re-déclarée nue dans les stages. Si
      // quelqu'un en écrivait une seconde avec un `=`, ce motif matcherait les deux et
      // ouvrirait des PR jumelles — symptôme à reconnaître plutôt qu'à déboguer.
      description: "ARG GH_VERSION (Dockerfile) — CLI GitHub, compilé chez le consommateur",
      customType: "regex",
      managerFilePatterns: ["/(^|/)Dockerfile$/"],
      // ⚠️ ANCRÉ EN DÉBUT DE LIGNE, et ce n'est pas cosmétique : un motif non ancré
      // matche aussi une ligne COMMENTÉE. Mesuré le 2026-09-14 — le Dockerfile
      // consommateur citait cet ARG dans une phrase d'avertissement, et Renovate en
      // extrayait une dépendance fantôme versionnée avec le reste de la phrase. Le
      // `[^\s#]` ferme au passage le commentaire de FIN de ligne, avalé sinon.
      matchStrings: ["(?m)^\\s*ARG GH_VERSION=(?<currentValue>[^\\s#]+)"],
      depNameTemplate: "cli/cli",
      datasourceTemplate: "github-releases",
      extractVersionTemplate: "^v(?<version>.*)$",
    },
  ],
  // Creds Harbor privé pour résoudre le digest du tag mouvant base/python.
  hostRules: [
    {
      matchHost: "registry-dev.soma-smart.cloud",
      hostType: "docker",
      username: process.env.HARBOR_USERNAME,
      password: process.env.HARBOR_PASSWORD,
    },
  ],
  packageRules: [
    {
      // Active le digest-pinning de la base. NE PAS gater par matchUpdateTypes :
      // la decision de pinner precede la connaissance de l'updateType, donc un
      // pinDigests derriere matchUpdateTypes ne genere jamais le pin (piege Renovate,
      // constate a l'E2E : une base non-pinnee restait non-pinnee).
      description: "Bases internes (DHI distroless + slim durci) : activer le digest-pinning",
      matchManagers: ["dockerfile"],
      matchPackageNames: [
        "registry-dev.soma-smart.cloud/base/python",
        "registry-dev.soma-smart.cloud/base/python-slim",
      ],
      pinDigests: true,
    },
    {
      description:
        "Bases internes (DHI + slim) : automerge digest/pin (gate = docker build sur PR ; org Free => merge cote Renovate)",
      matchManagers: ["dockerfile"],
      matchPackageNames: [
        "registry-dev.soma-smart.cloud/base/python",
        "registry-dev.soma-smart.cloud/base/python-slim",
      ],
      matchUpdateTypes: ["digest", "pinDigest"],
      automerge: true,
      automergeType: "pr",
      platformAutomerge: false,
    },
    {
      description:
        "Builders publics jetes (CVE non shippees), volontairement non suivis",
      matchManagers: ["dockerfile"],
      // ⚠️ SCOPÉ AUX STAGES INTERMÉDIAIRES, et c'est le point le plus important de
      // cette règle. Sans `matchDepTypes`, elle désactive le suivi de `golang` et
      // `python` PARTOUT, y compris sur un stage FINAL — donc sur une image
      // réellement livrée. La panne serait muette : aucune PR, indiscernable de
      // « rien à mettre à jour ». Le manager `dockerfile` distingue déjà les deux
      // (`depType: "stage"` vs `"final"`), il suffit de le lui demander.
      matchDepTypes: ["stage"],
      // ⚠️ `golang` y a ete ajoute avec le stage `gobuilder` de multica-runtime, et pas
      // par symetrie : sans cette entree, le manager `dockerfile` voit `golang:1.26`
      // (le defaut de BASE_REGISTRY est vide, le nom est donc nu) et ouvre des PR de
      // bump. Ce serait du bruit — mais surtout, un lecteur les « reglerait » un jour en
      // EPINGLANT le tag, ce qui recreerait exactement le gel que ce stage existe pour
      // fuir : c'est la reliaison avec une stdlib fraiche, a chaque build, qui permet de
      // corriger une CVE stdlib de `gh` par un simple rebuild.
      // ⚠️ `matchPackageNames` est en correspondance EXACTE : le nom nu ne couvre ni
      // `docker.io/library/...` ni le chemin du proxy Harbor. Les formes sont donc
      // listées, comme le fait déjà la règle Outline plus bas — sans quoi la règle
      // dépendrait du `BASE_REGISTRY` vide d'un AUTRE dépôt, couplage invisible d'ici.
      matchPackageNames: [
        "python",
        "golang",
        "docker.io/library/python",
        "docker.io/library/golang",
        "registry-dev.soma-smart.cloud/dockerhub-proxy/library/python",
        "registry-dev.soma-smart.cloud/dockerhub-proxy/library/golang",
      ],
      enabled: false,
    },
    {
      description:
        "Workflow réutilisable infra-datacenter-docs (référencé @main par TOUS les " +
        "consommateurs) : NON SUIVI À DESSEIN, incident du 2026-09-14",
      // ⚠️ CE DEP N'EST PAS EXCLU PAR PARESSE — la voie « donner accès à l'App » a été
      // TENTÉE, en production, et a eu un rayon de souffle inacceptable.
      //
      // Chaque consommateur référence
      //   uses: soma-smart/infra-datacenter-docs/.github/workflows/<X>.yml@main
      // — pinné sur une BRANCHE, jamais un SHA. Le manager `github-actions` tente donc
      // de résoudre le digest courant (datasource `github-digest`) pour proposer
      // l'épinglage — la même politique que la famille 2 de ce fichier — et échoue à
      // CHAQUE fois, sur TOUS les consommateurs, sur toutes leurs branches : l'App
      // `soma-base-bumper` (`repository_selection: "selected"`) n'a jamais eu accès à
      // `infra-datacenter-docs`, un dépôt PRIVÉ. Message GitHub, retrouvé dans la trace
      // GraphQL complète (pas le résumé) : « Could not resolve to a Repository with the
      // name 'soma-smart/infra-datacenter-docs'. » — la réponse standard à un jeton qui
      // ne VOIT PAS le dépôt, pas un 404 générique.
      //
      // ⚠️ AJOUTER `infra-datacenter-docs` À L'INSTALLATION DE L'APP A ÉTÉ ESSAYÉ ET
      // DÉFAIT LE MÊME JOUR. Avec `autodiscover: true` (racine de ce fichier), donner
      // à l'App la visibilité du dépôt ne lui donne pas qu'un accès en LECTURE au
      // digest : Renovate s'est mis à traiter `infra-datacenter-docs` comme un
      // consommateur COMPLET — 25+ dépendances scannées avec la politique de
      // `base-images` (pas la sienne), DEUX PR réellement ouvertes en quelques minutes
      // (#1500, #1505), une Dependency Dashboard parasite créée (#1510) en doublon de
      // la légitime (#1291, portée par `soma-renovate-infra`). Pire : la règle CVE de
      // ce fichier (`minimumReleaseAge: null` + automerge mineur/patch) se serait
      // appliquée au run planifié SUIVANT, fusionnant potentiellement dans `main`
      // d'`infra-datacenter-docs` via les gates de CE dépôt, sous l'identité et la
      // politique d'un AUTRE. Les 3 artefacts ont été nettoyés le jour même,
      // l'installation immédiatement retirée.
      //
      // ⚠️ UNE VOIE D'ACCÈS SCOPÉ EXISTE PEUT-ÊTRE (`autodiscoverFilter`), ET ELLE
      // N'A PAS ÉTÉ TESTÉE — trouvé en revue de #15, corrigeant une première rédaction
      // qui affirmait à tort son absence. `autodiscoverFilter` peut exclure un dépôt
      // de la liste que Renovate ITÈRE comme cible à gérer, SANS toucher à la
      // visibilité du jeton d'installation pour les lookups cross-repo faits pendant
      // le traitement d'un AUTRE dépôt — ce qui, en théorie, laisserait résoudre le
      // digest sans refaire gérer `infra-datacenter-docs` en entier.
      // ⚠️ DÉLIBÉRÉMENT NON INSTRUITE, PAS ÉCARTÉE PAR PREUVE : la vérifier exige de
      // REFAIRE le geste qui vient de coûter l'incident (ajouter l'App à
      // l'installation) — donc de reproduire le risque pour le tester, avant même de
      // savoir si `autodiscoverFilter` le referme réellement. Le coût d'une seconde
      // erreur au même endroit est plus grand que le bénéfice d'un digest résolu sur
      // une référence qui ne PEUT recevoir qu'un pin (cf. paragraphe suivant). Ne pas
      // relire ce commentaire comme « aucune voie n'existe » : il dit « non vérifiée,
      // et le coût de vérifier dépasse le bénéfice tant que ce `@main` ne bloque
      // rien de plus grave qu'une proposition de pin ».
      //
      // ⚠️ CE N'EST PAS UNE PERTE RÉELLE : ce `@main` ne PEUT rien recevoir d'autre
      // qu'une proposition d'épinglage SHA (aucune release, aucune version à comparer)
      // — la seule chose que Renovate pourrait jamais y faire est précisément ce qui
      // échoue. Si l'épinglage SHA de ce workflow partagé devient un jour nécessaire,
      // il doit être piloté par la boucle LÉGITIME d'`infra-datacenter-docs`
      // (`soma-renovate-infra`, dashboard #1291), qui a déjà l'accès et la politique
      // propres à ce dépôt — jamais par un ajout d'installation côté `base-images`.
      matchManagers: ["github-actions"],
      matchPackageNames: ["soma-smart/infra-datacenter-docs"],
      enabled: false,
    },
    {
      description:
        "github-actions (SHA-pinnees) : automerge minor/patch/digest, gate = CI du repo",
      matchManagers: ["github-actions"],
      matchUpdateTypes: ["minor", "patch", "digest", "pinDigest"],
      pinDigests: true,
      automerge: true,
      automergeType: "pr",
      platformAutomerge: false,
    },
    {
      description: "github-actions majors : revue via Dependency Dashboard",
      matchManagers: ["github-actions"],
      matchUpdateTypes: ["major"],
      dependencyDashboardApproval: true,
    },
    {
      // Corrections mineures/patch : automerge (gate = CI de l'app + docker build de
      // la PR, qui rebuild avec les nouvelles deps). minimumReleaseAge = maturation :
      // on n'automerge pas une version publiee il y a moins de 3 jours (protection
      // supply-chain contre un paquet compromis/yanked juste apres publication).
      description: "Deps applicatives pip/pep621 — mineur/patch : automerge (matures 3j)",
      matchManagers: ["pip_requirements", "pep621"],
      matchUpdateTypes: ["minor", "patch", "digest"],
      automerge: true,
      automergeType: "pr",
      platformAutomerge: false,
      minimumReleaseAge: "3 days",
      internalChecksFilter: "strict",
    },
    {
      description: "Deps applicatives pip/pep621 — majeur : PR, revue humaine",
      matchManagers: ["pip_requirements", "pep621"],
      matchUpdateTypes: ["major"],
      automerge: false,
    },
    // ═════════════════════════════════════════════════════════════════════════
    // Outline — cinquième famille. Le `FROM` de `soma-smart/outline` suit l'image
    // d'entreprise TIERCE ; son bump déclenche `build-and-bump.yml`, qui rebuild,
    // VÉRIFIE le crack de licence, pousse sur Harbor en `<version>-soma` et ouvre
    // la PR de bump dans l'infra.
    //
    // ⚠️ CES RÈGLES SONT ICI PARCE QU'ELLES NE SERVIRAIENT À RIEN DANS LE DÉPÔT.
    // `soma-smart/outline` porte depuis le 2026-06-29 un `renovate.json` correct
    // (mêmes deux règles) que `requireConfig: "ignored"` rend INERTE. Personne ne
    // l'a vu : le dépôt est resté hors de tout périmètre Renovate — ni ici, ni côté
    // App Mend — et Outline a filé de 1.8.1 à 1.9.2 (trois versions, cinq semaines)
    // sans une seule PR. Même panne que multica-runtime, même cause.
    // ⚠️ Cette config ne fait RIEN tant que l'App `soma-base-bumper` n'est pas
    // installée sur `soma-smart/outline` : `autodiscover` ne voit que ses
    // installations. Détection du cas général : #3913.
    //
    // ⚠️ L'automerge est ADOSSÉ À UN VRAI GATE, et il a fallu le créer : le workflow
    // ne se déclenchait que sur `push`, donc une PR de bump n'avait AUCUN check et
    // était mergée aussitôt. Un gate rouge après merge est muet — pas de publication,
    // aucun humain notifié (l'auteur du push est un bot), et le `Dockerfile` de `main`
    // portant déjà la version neuve, Renovate la considère à jour et ne la repropose
    // JAMAIS. `build-and-bump.yml` tourne désormais aussi sur `pull_request` (build +
    // vérification du crack, sans push) : c'est ce check que cet automerge attend.
    //
    // ⚠️ Les DEUX formes du nom sont listées à dessein. Le `FROM` cible
    // `index.docker.io/…`, et Renovate normalise les références Docker Hub : selon la
    // version, le nom porté par la règle est le chemin complet ou la forme courte. Un
    // `matchPackageNames` qui ne matche pas est un no-op SILENCIEUX — exactement la
    // panne qu'on corrige — alors qu'un nom listé en trop est simplement inerte.
    // ⚠️ Et surtout : ne PAS y remettre `docker.getoutline.com`. Cet hôte, pourtant
    // celui que documente l'éditeur, n'est qu'une redirection 302 vers Docker Hub, et
    // `got` (client HTTP de Renovate) largue l'en-tête `Authorization` au rebond
    // cross-origine : le listing des tags répond 401, Renovate ne voit aucune release
    // et son job reste VERT. Mesuré le 2026-08-13. Le `FROM` a été déplacé sur
    // `index.docker.io` pour cette raison — les deux vont ensemble.
    {
      description:
        "Outline enterprise — mineur/patch : automerge (matures 3j), gaté par le check de PR de build-and-bump",
      matchManagers: ["dockerfile"],
      matchPackageNames: [
        "index.docker.io/outlinewiki/outline-enterprise",
        "docker.io/outlinewiki/outline-enterprise",
        "outlinewiki/outline-enterprise",
      ],
      matchUpdateTypes: ["minor", "patch"],
      automerge: true,
      automergeType: "pr",
      platformAutomerge: false,
      minimumReleaseAge: "3 days",
      internalChecksFilter: "strict",
    },
    {
      description:
        "Outline enterprise — majeur : revue via Dependency Dashboard (variables d'env et config peuvent changer)",
      matchManagers: ["dockerfile"],
      matchPackageNames: [
        "index.docker.io/outlinewiki/outline-enterprise",
        "docker.io/outlinewiki/outline-enterprise",
        "outlinewiki/outline-enterprise",
      ],
      matchUpdateTypes: ["major"],
      dependencyDashboardApproval: true,
    },
    // ═════════════════════════════════════════════════════════════════════════
    // Épingles regex — la famille 4. ⚠️ ÉCRITE EXPLICITEMENT, ET C'EST LE POINT :
    // toutes les règles ci-dessus gatent sur `matchManagers`, or un dep extrait
    // par un manager regex se déclare `custom.regex` et ne matche AUCUNE d'entre
    // elles. Sans cette règle, la famille n'hériterait de rien — pas de
    // maturation supply-chain, pas de revue des majeurs — soit exactement
    // l'inverse de la politique appliquée partout ailleurs, et sans que rien
    // ne le signale.
    // ═════════════════════════════════════════════════════════════════════════
    {
      // Maturation supply-chain, comme pip/pep621 : on n'ouvre pas de PR sur une
      // version publiée il y a moins de 3 jours (protection contre un paquet
      // compromis ou retiré juste après publication). ⚠️ Utile ici en
      // particulier : `claude-code` publie très fréquemment, et sans ce délai la
      // PR serait rebasée en permanence pour du bruit.
      description: "Épingles regex — maturation 3j, JAMAIS d'automerge",
      matchManagers: ["custom.regex"],
      minimumReleaseAge: "3 days",
      internalChecksFilter: "strict",
      // ⚠️ Pas d'automerge, à dessein, et contrairement aux trois autres familles.
      // Ce que ces épingles gouvernent n'est pas une dépendance applicative
      // ordinaire : le daemon qui EXÉCUTE les tâches de l'agent, la CLI qu'il
      // fait tourner, et le scanner censé prouver que l'image est saine. Et le
      // bump de multica part ROUGE par construction (hash non calculable) : un
      // automerge n'aurait de toute façon jamais lieu, mais mieux vaut que ce
      // soit une décision qu'un effet de bord.
      automerge: false,
    },
    {
      description: "Épingles regex — majeur : revue via Dependency Dashboard",
      matchManagers: ["custom.regex"],
      matchUpdateTypes: ["major"],
      dependencyDashboardApproval: true,
    },
  ],
};
