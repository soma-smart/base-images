// Contre-test des motifs `multica` de renovate-config.js, joué DANS l'image Renovate.
//
// ⚠️ Pourquoi dans l'image : `(?m)` n'existe pas dans le RegExp de JS, seulement dans RE2,
// que Renovate charge en natif. Hors image, ce test refuserait le motif lui-même.
// ⚠️ Pourquoi ce test existe : un manager regex qui ne matche RIEN est valide et muet
// (zéro erreur, zéro PR) — la panne du 2026-08-11. `renovate-config-validator` et le
// contrôle « manager/motifs appariés » ne le voient pas. Ici on prouve, sur des
// Dockerfile types, qu'EXACTEMENT UN motif matche, et une seule fois.
//
// Entrées : config sur /tmp/renovate-config.js ; REGEX_JS (défaut : chemin de l'image).
import { createRequire } from "module";

const { regEx } = await import(process.env.REGEX_JS || "/usr/local/renovate/dist/util/regex.js");
const config = createRequire("/tmp/")("/tmp/renovate-config.js");
const motifs = config.customManagers.filter((m) => m.depNameTemplate === "multica-ai/multica");
if (motifs.length === 0) {
  console.error("::error::aucun customManager multica-ai/multica");
  process.exit(1);
}

const H = "e".repeat(64);
const deps = (texte) =>
  motifs.flatMap((m) =>
    m.matchStrings.flatMap((s) => [...texte.matchAll(regEx(s, "g"))].map((r) => r.groups)),
  );
let echecs = 0;
const cas = (nom, texte, attendu, verif) => {
  const d = deps(texte);
  if (d.length !== attendu || (verif && !verif(d))) {
    console.error(`::error::${nom} : ${d.length} dep(s) au lieu de ${attendu} — ${JSON.stringify(d)}`);
    echecs += 1;
  } else {
    console.log(`OK  ${nom}`);
  }
};

const entete = "# commentaire\nFROM scratch\n";
cas("paire v…", `${entete}ARG MULTICA_VERSION=v0.6.2\nARG MULTICA_SHA256=${H}\nRUN true\n`, 1,
  (d) => d[0].currentValue === "v0.6.2" && d[0].currentDigest === H);
cas("lignes commentées", `# ARG MULTICA_VERSION=v0.6.2\n# ARG MULTICA_SHA256=${H}\n`, 0);
// Ce cas garde l'ANCRAGE `^` du motif : sans lui, une version commentée suivie d'un hash
// actif serait lue comme une paire.
cas("version commentée, hash actif", `# ARG MULTICA_VERSION=v0.6.2\nARG MULTICA_SHA256=${H}\n`, 0);
cas("indentée (stage)", `${entete}  ARG MULTICA_VERSION=v0.6.2\n  ARG MULTICA_SHA256=${H}\n`, 1);

// LIMITES CONNUES : ces formes ne sont PAS suivies, en silence. Elles sont figées ici pour
// qu'élargir le motif soit un geste délibéré ; la garde de l'amont est dans multica-runtime
// (`build.yml`, étape « Paire MULTICA_VERSION / MULTICA_SHA256 »), pas dans cette config.
cas("limite : commentaire entre les deux ARG", `ARG MULTICA_VERSION=v0.6.2\n# note\nARG MULTICA_SHA256=${H}\n`, 0);
cas("limite : ordre inversé", `ARG MULTICA_SHA256=${H}\nARG MULTICA_VERSION=v0.6.2\n`, 0);
cas("limite : CRLF", `ARG MULTICA_VERSION=v0.6.2\r\nARG MULTICA_SHA256=${H}\r\n`, 0);
cas("limite : version sans v", `ARG MULTICA_VERSION=0.6.2\nARG MULTICA_SHA256=${H}\n`, 0);
cas("limite : hash en majuscules", `ARG MULTICA_VERSION=v0.6.2\nARG MULTICA_SHA256=${H.toUpperCase()}\n`, 0);

if (echecs) process.exit(1);
console.log("OK - motifs multica");
