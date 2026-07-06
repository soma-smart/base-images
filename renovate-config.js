// Config GLOBAL du Renovate self-hosted (boucle de remédiation CVE).
//
// Ce Renovate ne gère QU'UNE chose : le digest de la base DHI interne
// (registry-dev.soma-smart.cloud/base/python) dans le FROM runtime des apps.
// Dependabot / Mend SaaS restent maîtres du reste (pip, github-actions, builder
// slim public) — eux ne peuvent pas atteindre le Harbor interne, d'où ce Renovate.
//
// Portée : autodiscover sur les repos où la GitHub App `soma-base-bumper` est
// installée (= som-portal, agent-infogerance). enabledManagers dockerfile + match
// de la seule base => aucun recouvrement avec Dependabot/Mend, aucun renovate.json
// par repo requis (rien n'est écrasé).
module.exports = {
  platform: "github",
  autodiscover: true,
  onboarding: false,
  requireConfig: "optional",
  dependencyDashboard: false,
  enabledManagers: ["dockerfile"],
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
        "Builder slim public : geré par Dependabot, ce Renovate ne le touche pas",
      matchManagers: ["dockerfile"],
      matchPackageNames: ["python"],
      enabled: false,
    },
  ],
};
