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
//   3. deps applicatives (pip/pep621) -> PR, revue humaine
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
      description:
        "Base DHI interne : automerge digest-only (gate = docker build sur PR ; org Free => merge cote Renovate)",
      matchManagers: ["dockerfile"],
      matchPackageNames: ["registry-dev.soma-smart.cloud/base/python"],
      pinDigests: true,
      automerge: true,
      automergeType: "pr",
      platformAutomerge: false,
      matchUpdateTypes: ["digest", "pinDigest"],
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
      description: "Deps applicatives (pip/pep621) : PR, revue humaine (pas d'automerge)",
      matchManagers: ["pip_requirements", "pep621"],
      automerge: false,
    },
  ],
};
