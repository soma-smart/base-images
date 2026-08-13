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
  // Dashboard actif : surface les "Dependency Lookup Warnings" (ex. échec d'auth
  // Harbor sur hostRules) qui, sinon, rendent la boucle muette sans erreur de job.
  dependencyDashboard: true,
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
      matchStrings: ["ARG MULTICA_VERSION=(?<currentValue>.*?)\\n"],
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
      matchStrings: ["ARG CLAUDE_CODE_VERSION=(?<currentValue>.*?)\\n"],
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
      description: "TRIVY_VERSION (workflow de build) — scanner d'images",
      customType: "regex",
      managerFilePatterns: ["/^\\.github/workflows/.*\\.ya?ml$/"],
      matchStrings: ["TRIVY_VERSION: *[\"']?(?<currentValue>[^\"'\\s]+)[\"']?"],
      depNameTemplate: "aquasecurity/trivy",
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
        "Builder slim public : stage jete (CVE non shippees), volontairement non suivi",
      matchManagers: ["dockerfile"],
      matchPackageNames: ["python"],
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
    // ⚠️ Le gate de ce bump est POST-MERGE, contrairement aux trois autres familles
    // dont le gate est un check de PR. C'est inhérent à la chaîne : la vérification
    // du crack exige de CONSTRUIRE l'image, et `build-and-bump.yml` ne se déclenche
    // que sur `push` vers `main` (`paths: ["Dockerfile"]`). Un gate rouge n'empêche
    // donc pas le merge, il arrête la publication — pas de push Harbor, pas de PR
    // infra. Ne pas « réparer » ça en retirant l'automerge : ça figerait Outline
    // sans rien protéger de plus.
    {
      description:
        "Outline enterprise — mineur/patch : automerge (matures 3j). Gate = build-and-bump POST-merge.",
      matchManagers: ["dockerfile"],
      matchPackageNames: ["docker.getoutline.com/outlinewiki/outline-enterprise"],
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
      matchPackageNames: ["docker.getoutline.com/outlinewiki/outline-enterprise"],
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
