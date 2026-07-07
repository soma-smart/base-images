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
  enabledManagers: ["dockerfile", "pip_requirements", "pep621", "github-actions"],
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
