// Config GLOBAL et UNIQUE du Renovate self-hosted (boucle de remédiation CVE).
//
// Modèle homogène (2026-07-06) : UN SEUL outil de gestion des dépendances sur tous
// les repos d'apps — Renovate self-hosted. Plus de Dependabot, plus de renovate.json
// par repo. Ce fichier est la seule source de vérité (requireConfig: "ignored" =>
// les éventuels renovate.json résiduels des repos sont ignorés).
//
// Portée : autodiscover sur les repos où la GitHub App `soma-base-bumper` est
// installée (= les consommateurs). Trois familles de mises à jour, uniformes partout :
//   1. digest de la base DHI interne  -> automerge (gate = ci-docker-build sur PR)
//   2. github-actions (SHA-pinnées)   -> automerge minor/patch/digest, majors en dashboard
//   3. deps applicatives (pip/pep621) -> mineur/patch automerge (matures 3j), majeur en PR
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
  // déclarer un MOTIF que tout dépôt peut adopter en écrivant la ligne.
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
      managerFilePatterns: ["/^Dockerfile$/"],
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
      managerFilePatterns: ["/^Dockerfile$/"],
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
      managerFilePatterns: ["/^\\.github/workflows/build\\.yml$/"],
      matchStrings: ["TRIVY_VERSION: \"(?<currentValue>.*?)\""],
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
  ],
};
