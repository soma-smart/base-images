#!/usr/bin/env python3
"""Exerce `bump_trivy.py` dans ses modes d'ECHEC : chaque cas est un chemin par lequel le script conclurait « à jour » (ou
ouvrirait la mauvaise PR) sans rien avoir prouvé. Aucun accès réseau : l'API, git et l'horloge sont injectés."""
import http.client
import io
import json
import os
import sys
import tempfile
import urllib.error
from contextlib import contextmanager, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import bump_trivy as b  # noqa: E402

MAINTENANT = datetime(2026, 11, 10, 12, 0, 0, tzinfo=timezone.utc)


def rel(tag, jours, assets=True, **kw):
    """Une release de l'API GitHub, publiée il y a `jours` jours (flottant accepté)."""
    version = tag.lstrip("v")
    r = {"tag_name": tag, "draft": False, "prerelease": False,
         "published_at": (MAINTENANT - timedelta(days=jours)).strftime("%Y-%m-%dT%H:%M:%SZ"),
         "html_url": f"https://github.com/aquasecurity/trivy/releases/tag/{tag}",
         "assets": [{"name": f"trivy_{version}_Linux-64bit.tar.gz"}, {"name": f"trivy_{version}_checksums.txt"}] if assets else []}
    r.update(kw)
    return r


def courante(s):
    return b.version_tuple(s)


def erreur(nom, fonction, fragment):
    """`fonction` DOIT lever BumpError dont le message contient `fragment` : sinon ce serait un faux « à jour »."""
    try:
        fonction()
    except b.BumpError as e:
        assert fragment in str(e), f"{nom} : message attendu '{fragment}', reçu '{e}'"
        return
    raise AssertionError(f"{nom} : aucune erreur levée, le script aurait conclu sans preuve")


class Reponse:
    def __init__(self, contenu):
        self.contenu = contenu if isinstance(contenu, bytes) else json.dumps(contenu).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self.contenu


# ---------------------------------------------------------------- choisir
def test_choix_nominal():
    cible, _ = b.choisir([rel("v0.77.0", 10), rel("v0.76.2", 20), rel("v0.76.1", 30)], courante("0.76.1"), MAINTENANT)
    assert cible and cible["version"] == "0.77.0", cible


def test_ignore_brouillons_prereleases_et_tags_inconnus():
    liste = [rel("v0.80.0", 10, draft=True), rel("v0.79.0", 10, prerelease=True), rel("nightly", 10),
             rel("v0.78.0-rc.1", 10), rel("0.77.0", 10), rel("v0.76.2", 10), rel("v0.76.1", 30)]
    cible, _ = b.choisir(liste, courante("0.76.1"), MAINTENANT)
    assert cible and cible["version"] == "0.76.2", cible


def test_maturite():
    # une version plus récente mais immature ne masque pas une version mûre plus ancienne
    cible, _ = b.choisir([rel("v0.77.0", 1), rel("v0.76.2", 10)], courante("0.76.1"), MAINTENANT)
    assert cible and cible["version"] == "0.76.2", cible
    # seulement des versions immatures : on attend
    cible, raison = b.choisir([rel("v0.77.0", 1), rel("v0.76.1", 30)], courante("0.76.1"), MAINTENANT)
    assert cible is None and "maturité" in raison, (cible, raison)
    # frontière : exactement 3 jours = mûre ; 2 j 23 h = pas encore
    cible, _ = b.choisir([rel("v0.77.0", 3), rel("v0.76.1", 30)], courante("0.76.1"), MAINTENANT)
    assert cible and cible["version"] == "0.77.0"
    cible, _ = b.choisir([rel("v0.77.0", 3 - 1 / 24), rel("v0.76.1", 30)], courante("0.76.1"), MAINTENANT)
    assert cible is None


def test_jamais_de_retour_en_arriere():
    for actuelle in ("0.76.1", "0.99.0"):
        cible, raison = b.choisir([rel("v0.76.1", 30), rel("v0.76.0", 40)], courante(actuelle), MAINTENANT)
        assert cible is None and "à jour" in raison, (actuelle, cible, raison)


def test_chiffres_unicode_refuses():
    erreur("version en chiffres arabes", lambda: b.version_tuple("٣.٤.٥"), "version invalide")
    cible, _ = b.choisir([rel("v٣.٤.٥", 10), rel("v0.76.1", 30)], courante("0.76.1"), MAINTENANT)
    assert cible is None, "un tag en chiffres Unicode ne doit jamais être proposé"


def test_comparaison_numerique_pas_lexicale():
    cible, _ = b.choisir([rel("v0.9.0", 40), rel("v0.10.0", 30)], courante("0.9.0"), MAINTENANT)
    assert cible and cible["version"] == "0.10.0", cible


def test_echecs_de_lecture_sont_rouges():
    erreur("liste vide", lambda: b.choisir([], courante("0.76.1"), MAINTENANT), "réponse inattendue")
    erreur("l'API renvoie un objet d'erreur", lambda: b.choisir({"message": "rate limited"}, courante("0.76.1"), MAINTENANT),
           "réponse inattendue")
    erreur("entrée sans tag_name", lambda: b.choisir([{"name": "x"}], courante("0.76.1"), MAINTENANT), "tag_name")
    erreur("aucune release stable reconnue", lambda: b.choisir([rel("nightly", 1), rel("v0.77.0-rc.1", 1)],
                                                              courante("0.76.1"), MAINTENANT), "aucune release stable")
    erreur("date illisible", lambda: b.choisir([rel("v0.77.0", 10, published_at="hier")], courante("0.76.1"), MAINTENANT),
           "published_at illisible")
    erreur("date absente", lambda: b.choisir([rel("v0.77.0", 10, published_at=None)], courante("0.76.1"), MAINTENANT),
           "published_at illisible")


def test_release_mure_sans_ses_fichiers_est_rouge():
    erreur("assets absents", lambda: b.choisir([rel("v0.77.0", 10, assets=False)], courante("0.76.1"), MAINTENANT), "absents")
    seulement_archive = rel("v0.77.0", 10)
    seulement_archive["assets"] = seulement_archive["assets"][:1]
    erreur("fichier de sommes absent", lambda: b.choisir([seulement_archive], courante("0.76.1"), MAINTENANT),
           "checksums.txt")
    # ... mais une release IMMATURE sans fichiers n'est pas encore un problème (publication en cours)
    cible, _ = b.choisir([rel("v0.77.0", 0.5, assets=False), rel("v0.76.2", 10)], courante("0.76.1"), MAINTENANT)
    assert cible and cible["version"] == "0.76.2"


# ---------------------------------------------------------------- version courante
def test_lecture_de_la_version_courante():
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / ".trivy-version"
        for contenu, ok in (("0.76.1\n", True), ("0.76.1", True), ("0.76.1\n\n", True), ("", False), ("v0.76.1\n", False),
                            ("0.76\n", False), ("0.76.1\n0\n", False), ("0.76.1 0.77.0\n", False), ("latest\n", False)):
            f.write_text(contenu)
            try:
                v = b.lire_courante(f)
                assert ok and v == "0.76.1", (contenu, v)
            except b.BumpError:
                assert not ok, f"{contenu!r} aurait dû être accepté"


# ---------------------------------------------------------------- lecture anonyme des releases
def test_requete_anonyme_sans_en_tete_authorization():
    vues = []

    def ouvrir(req, timeout):
        vues.append(req)
        return Reponse([rel("v0.76.1", 30)])
    b.releases_anonymes(ouvrir=ouvrir, dormir=lambda s: None)
    assert len(vues) == 1 and vues[0].full_url == b.URL_RELEASES
    tous = {k.lower() for k in vues[0].headers} | {k.lower() for k in vues[0].unredirected_hdrs}
    assert "authorization" not in tous, "la requête à l'API de Trivy ne doit JAMAIS porter de jeton (IP allow list)"
    assert not any(k.lower() == "authorization" for k, _ in vues[0].header_items())


def test_main_lit_les_releases_par_la_voie_anonyme():
    """Tous les autres tests de main() injectent `releases=` : sans celui-ci, rien ne prouvait que main() n'allait pas lire
    l'API de Trivy par la classe `Github` (qui, elle, porte le jeton)."""
    appels = []
    ancien = b.releases_anonymes
    b.releases_anonymes = lambda: appels.append("anonyme") or [rel("v0.76.1", 30)]
    try:
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / ".trivy-version"
            f.write_text("0.76.1\n")
            with redirect_stdout(io.StringIO()):
                b.main([], fichier=f, maintenant=MAINTENANT)
    finally:
        b.releases_anonymes = ancien
    assert appels == ["anonyme"], appels


def test_reprises_et_abandon():
    def sequence(*evenements):
        appels = []

        def ouvrir(req, timeout):
            appels.append(1)
            e = evenements[min(len(appels), len(evenements)) - 1]
            if isinstance(e, Exception):
                raise e
            return Reponse(e)
        return ouvrir, appels

    dormis = []
    ouvrir, appels = sequence(urllib.error.URLError("dns"), urllib.error.URLError("dns"), [rel("v0.76.1", 30)])
    assert b.releases_anonymes(ouvrir=ouvrir, dormir=dormis.append) and len(appels) == 3 and len(dormis) == 2
    ouvrir, appels = sequence(urllib.error.URLError("dns"))
    erreur("échec persistant", lambda: b.releases_anonymes(ouvrir=ouvrir, dormir=lambda s: None), "après 3 essais")
    assert len(appels) == 3
    ouvrir, appels = sequence(b"pas du json")
    erreur("JSON invalide", lambda: b.releases_anonymes(ouvrir=ouvrir, dormir=lambda s: None), "après 3 essais")
    http500 = urllib.error.HTTPError(b.URL_RELEASES, 500, "x", {}, io.BytesIO(b""))
    ouvrir, appels = sequence(http500, [rel("v0.76.1", 30)])
    assert b.releases_anonymes(ouvrir=ouvrir, dormir=lambda s: None) and len(appels) == 2
    # quota / refus d'IP : pas de nouvel essai (il ne changerait rien)
    http403 = urllib.error.HTTPError(b.URL_RELEASES, 403, "x", {}, io.BytesIO(b""))
    ouvrir, appels = sequence(http403)
    erreur("403", lambda: b.releases_anonymes(ouvrir=ouvrir, dormir=lambda s: None), "HTTP 403")
    assert len(appels) == 1


def test_erreurs_pendant_la_lecture_de_la_reponse_sont_rejouees():
    class LectureCassee(Reponse):
        def __init__(self, erreur):
            self.erreur = erreur

        def read(self):
            raise self.erreur

    for erreur_lecture in (ConnectionResetError("reset"), http.client.IncompleteRead(b"x"),
                           UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalide"), TimeoutError("lent")):
        appels = []

        def ouvrir(req, timeout, e=erreur_lecture):
            appels.append(1)
            return LectureCassee(e) if len(appels) == 1 else Reponse([rel("v0.76.1", 30)])
        assert b.releases_anonymes(ouvrir=ouvrir, dormir=lambda s: None) and len(appels) == 2, type(erreur_lecture).__name__
    # et si elle ne se rétablit jamais : rouge, avec le message de BumpError (pas un traceback brut)
    erreur("lecture cassée en permanence",
           lambda: b.releases_anonymes(ouvrir=lambda req, timeout: LectureCassee(ConnectionResetError("reset")), dormir=lambda s: None),
           "après 3 essais")


# ---------------------------------------------------------------- API de NOTRE dépôt
def test_api_depot_porte_le_jeton_et_explique_le_refus_de_creer_une_pr():
    vues = []

    def ouvrir(req, timeout):
        vues.append(req)
        return Reponse(b"")
    api = b.Github("soma-smart/base-images", "JETON", ouvrir=ouvrir)
    assert api("POST", "/actions/workflows/x.yml/dispatches", {"ref": "r"}) is None
    assert vues[0].get_method() == "POST" and vues[0].get_header("Authorization") == "Bearer JETON"
    assert "api.github.com/repos/soma-smart/base-images/actions" in vues[0].full_url

    def refuse(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 403, "x", {}, io.BytesIO(b'{"message":"not permitted"}'))
    erreur("création de PR refusée", lambda: b.Github("o/r", "J", ouvrir=refuse)("POST", "/pulls", {}),
           "Allow GitHub Actions to create and approve pull requests")
    erreur("autre refus", lambda: b.Github("o/r", "J", ouvrir=refuse)("GET", "/pulls"), "HTTP 403")
    # réseau / délai / réponse illisible : une erreur lisible (`::error::`), pas un traceback
    for e in (urllib.error.URLError("dns"), TimeoutError("lent"), http.client.IncompleteRead(b"x"), ConnectionResetError("reset")):
        def casse(req, timeout, e=e):
            raise e
        erreur(type(e).__name__, lambda: b.Github("o/r", "J", ouvrir=casse)("GET", "/pulls"), type(e).__name__)
    erreur("corps non JSON", lambda: b.Github("o/r", "J", ouvrir=lambda req, timeout: Reponse(b"<html>"))("GET", "/pulls"),
           "JSONDecodeError")
    # un 5xx garde son code HTTP dans le message (l'ordre des `except` : HTTPError avant sa classe mère URLError)
    def http500(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 500, "x", {}, io.BytesIO(b"boom"))
    erreur("HTTP 500", lambda: b.Github("o/r", "J", ouvrir=http500)("GET", "/pulls"), "HTTP 500 boom")


# ---------------------------------------------------------------- ouverture de la PR
CIBLE = {"version": "0.77.0", "publiee": "2026-11-01T10:00:00Z", "url": "https://example/release"}


def faux(pulls_existantes=None, ls_remote=2, echec_sur=None):
    """API et git simulés. `ordre` : la suite EXACTE des appels (git et API mêlés), pour verrouiller l'ordre des étapes."""
    appels = {"api": [], "git": [], "ordre": []}

    def api(methode, chemin, corps=None):
        appels["api"].append((methode, chemin, corps))
        appels["ordre"].append(f"{methode} {chemin}")
        if echec_sur and methode == "POST" and chemin == echec_sur:
            raise b.BumpError(f"{chemin} refusé")
        return pulls_existantes if methode == "GET" else None

    def executer_git(args, tolerer=(0,)):
        appels["git"].append(args)
        appels["ordre"].append("git " + next(a for a in args if a in ("ls-remote", "switch", "add", "commit", "push")))
        return ls_remote if args[0] == "ls-remote" else 0
    return api, executer_git, appels


DISPATCH_BUILD = "POST /actions/workflows/build-python-slim.yml/dispatches"
DISPATCH_COPIE = "POST /actions/workflows/copie-alpine.yml/dispatches"


def test_pr_fraiche_pousse_ouvre_et_lance_la_ci():
    api, g, appels = faux(pulls_existantes=[])
    assert b.ouvrir_pr("0.76.1", CIBLE, api=api, executer_git=g, proprietaire="soma-smart") == "ouverte"
    verbes = [a[0] for a in appels["git"]]
    assert verbes[:1] == ["ls-remote"] and "switch" in verbes and "add" in verbes and "push" in verbes
    assert any("commit" in a for a in appels["git"])
    assert appels["git"][-1] == ["push", "origin", "bump/trivy-0.77.0"], appels["git"][-1]
    pr = [a for a in appels["api"] if a[:2] == ("POST", "/pulls")]
    assert len(pr) == 1 and pr[0][2]["head"] == "bump/trivy-0.77.0" and pr[0][2]["base"] == "main"
    assert "0.76.1 → 0.77.0" in pr[0][2]["title"]
    lances = [a[1] for a in appels["api"] if "/dispatches" in a[1]]
    assert lances == [f"/actions/workflows/{w}/dispatches" for w in b.WORKFLOWS_CI], lances
    assert all(a[2] == {"ref": "bump/trivy-0.77.0"} for a in appels["api"] if "/dispatches" in a[1])
    # L'ORDRE est la garantie : branche poussée → CI lancée → PR créée (jamais la PR avant la CI, cf. test suivant)
    ordre = appels["ordre"]
    assert ordre.index("git push") < ordre.index(DISPATCH_BUILD) < ordre.index(DISPATCH_COPIE) < ordre.index("POST /pulls"), ordre


def test_echec_du_lancement_laisse_une_branche_sans_pr_et_le_run_suivant_reprend():
    """Si la PR était créée AVANT la CI, un lancement raté la laisserait sans aucun check, et le run suivant sortirait vert."""
    api, g, appels = faux(pulls_existantes=[], ls_remote=2, echec_sur="/actions/workflows/copie-alpine.yml/dispatches")
    erreur("2ᵉ lancement en échec", lambda: b.ouvrir_pr("0.76.1", CIBLE, api=api, executer_git=g, proprietaire="soma-smart"),
           "copie-alpine.yml/dispatches")
    assert "git push" in appels["ordre"] and "POST /pulls" not in appels["ordre"], \
        f"aucune PR ne doit exister quand la CI n'a pas pu être lancée : {appels['ordre']}"
    # run suivant : la branche existe déjà (ls-remote = 0), toujours sans PR → pas de repush, CI relancée, PR ouverte
    api, g, appels = faux(pulls_existantes=[], ls_remote=0)
    assert b.ouvrir_pr("0.76.1", CIBLE, api=api, executer_git=g, proprietaire="soma-smart") == "ouverte"
    ordre = appels["ordre"]
    assert "git push" not in ordre and "git commit" not in ordre, ordre
    assert ordre.index(DISPATCH_BUILD) < ordre.index(DISPATCH_COPIE) < ordre.index("POST /pulls"), ordre
    # 1ᵉʳ lancement en échec : même garantie
    api, g, appels = faux(pulls_existantes=[], echec_sur="/actions/workflows/build-python-slim.yml/dispatches")
    erreur("1ᵉʳ lancement en échec", lambda: b.ouvrir_pr("0.76.1", CIBLE, api=api, executer_git=g, proprietaire="soma-smart"),
           "build-python-slim.yml/dispatches")
    assert "POST /pulls" not in appels["ordre"] and DISPATCH_COPIE not in appels["ordre"], appels["ordre"]


def test_workflows_lances_existent_et_se_lancent_a_la_main():
    """Un nom de fichier faux ou un workflow sans `workflow_dispatch` ferait échouer le lancement APRÈS le push, à chaque run."""
    dossier = Path(__file__).resolve().parent.parent / ".github" / "workflows"
    for nom in b.WORKFLOWS_CI:
        assert (dossier / nom).exists(), f"{nom} n'existe pas dans .github/workflows"
        assert "workflow_dispatch" in (dossier / nom).read_text(), f"{nom} n'a pas de déclencheur workflow_dispatch"


def test_helper_git_fail_closed():
    class Termine:
        def __init__(self, code):
            self.returncode = code
    ancien = b.subprocess.run
    try:
        for code, tolerer, attendu in ((0, (0,), 0), (2, (0, 2), 2), (2, (0,), None), (128, (0, 2), None), (1, (0,), None)):
            b.subprocess.run = lambda cmd, check, c=code: Termine(c)
            if attendu is None:
                erreur(f"git code {code}", lambda: b.git(["push", "origin", "x"], tolerer=tolerer), f"code {code}")
            else:
                assert b.git(["ls-remote"], tolerer=tolerer) == attendu
    finally:
        b.subprocess.run = ancien


def test_jamais_de_dispatch_de_mirror_dhi():
    assert "mirror-dhi.yml" not in b.WORKFLOWS_CI, "mirror-dhi publie vers Harbor sans garde de branche"
    api, g, appels = faux(pulls_existantes=[])
    b.ouvrir_pr("0.76.1", CIBLE, api=api, executer_git=g, proprietaire="soma-smart")
    assert not any("mirror-dhi" in a[1] for a in appels["api"])


def test_idempotence_une_pr_fermee_est_un_refus():
    api, g, appels = faux(pulls_existantes=[{"number": 1, "state": "closed"}])
    assert b.ouvrir_pr("0.76.1", CIBLE, api=api, executer_git=g, proprietaire="soma-smart") == "existe"
    assert appels["git"] == [] and not any(a[0] == "POST" for a in appels["api"]), "aucune écriture attendue"
    # la recherche porte sur TOUS les états, sinon une PR fermée serait rouverte chaque jour
    assert "state=all" in appels["api"][0][1] and "soma-smart:bump/trivy-0.77.0" in appels["api"][0][1]


def test_branche_poussee_sans_pr_reprend_sans_repousser():
    api, g, appels = faux(pulls_existantes=[], ls_remote=0)
    assert b.ouvrir_pr("0.76.1", CIBLE, api=api, executer_git=g, proprietaire="soma-smart") == "ouverte"
    assert [a[0] for a in appels["git"]] == ["ls-remote"], "ni commit ni push : la branche existe déjà"
    assert any(a[:2] == ("POST", "/pulls") for a in appels["api"])


def test_pr_refusee_leve_apres_la_ci_et_se_reprend():
    # La CI est lancée AVANT la PR : si la création est refusée (réglage d'organisation), le run est rouge, la branche et la CI
    # existent déjà, et le run suivant n'aura que la PR à ouvrir (branche présente → pas de repush).
    api, g, appels = faux(pulls_existantes=[], echec_sur="/pulls")
    erreur("création de PR refusée", lambda: b.ouvrir_pr("0.76.1", CIBLE, api=api, executer_git=g, proprietaire="soma-smart"),
           "refusé")
    assert DISPATCH_BUILD in appels["ordre"] and DISPATCH_COPIE in appels["ordre"]


def test_corps_de_pr_dit_la_limite_de_la_ci():
    corps = b.corps_pr("0.76.1", CIBLE, "bump/trivy-0.77.0")
    for fragment in ("0.76.1 → 0.77.0", "build-python-slim.yml", "copie-alpine.yml", "mirror-dhi", "Fermer la PR", "https://example/release"):
        assert fragment in corps, fragment


# ---------------------------------------------------------------- main
def lancer_main(argv, fichier_contenu="0.76.1\n", releases=None, env=None):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / ".trivy-version"
        f.write_text(fichier_contenu)
        sortie_gh = Path(d) / "sortie"
        ancien = {k: os.environ.get(k) for k in ("GITHUB_OUTPUT", "GITHUB_TOKEN")}
        os.environ["GITHUB_OUTPUT"] = str(sortie_gh)
        os.environ.pop("GITHUB_TOKEN", None)
        os.environ.update(env or {})
        tampon = io.StringIO()
        try:
            with redirect_stdout(tampon):
                code = b.main(argv, fichier=f, maintenant=MAINTENANT, releases=releases)
        finally:
            for k, v in ancien.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        return code, tampon.getvalue(), f.read_text(), sortie_gh.read_text() if sortie_gh.exists() else ""


def test_simulation_n_ecrit_rien():
    code, sortie, contenu, gh = lancer_main(["--simuler-version-courante", "0.75.0"],
                                            releases=[rel("v0.77.0", 10), rel("v0.76.1", 30)])
    assert code == 0 and contenu == "0.76.1\n", "la simulation ne doit pas toucher .trivy-version"
    assert "[SIMULATION]" in sortie and "bump/trivy-0.77.0" in sortie and "0.75.0 → 0.77.0" in sortie
    assert "bump=true" in gh and "cible=0.77.0" in gh
    erreur("version simulée invalide", lambda: lancer_main(["--simuler-version-courante", "0.75"], releases=[rel("v0.77.0", 10)]),
           "version invalide")


def test_a_jour_sort_en_vert_et_le_dit():
    code, sortie, contenu, gh = lancer_main([], releases=[rel("v0.76.1", 30)])
    assert code == 0 and "à jour" in sortie and "bump=false" in gh and contenu == "0.76.1\n"


@contextmanager
def env_isole(dossier):
    """Sans GITHUB_TOKEN, avec un GITHUB_OUTPUT jetable : le test ne touche jamais la sortie du step CI réel, et l'environnement
    d'origine est RESTAURÉ (un `pop` sec laisserait le jeton supprimé pour les tests suivants)."""
    noms = ("GITHUB_OUTPUT", "GITHUB_TOKEN")
    ancien = {k: os.environ.get(k) for k in noms}
    os.environ["GITHUB_OUTPUT"] = str(Path(dossier) / "sortie")
    os.environ.pop("GITHUB_TOKEN", None)
    try:
        yield
    finally:
        for k, v in ancien.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_jeton_absent_est_rouge_et_n_ecrit_rien():
    with tempfile.TemporaryDirectory() as d, env_isole(d):
        f = Path(d) / ".trivy-version"
        f.write_text("0.76.1\n")
        with redirect_stdout(io.StringIO()):
            erreur("jeton absent", lambda: b.main([], fichier=f, maintenant=MAINTENANT,
                                                  releases=[rel("v0.77.0", 10), rel("v0.76.1", 30)]), "GITHUB_TOKEN absent")
        assert f.read_text() == "0.76.1\n", "le fichier ne doit pas être modifié avant d'avoir de quoi ouvrir la PR"


def test_main_propage_les_echecs_de_lecture():
    erreur("liste vide", lambda: lancer_main([], releases=[]), "réponse inattendue")
    erreur("fichier de version invalide", lambda: lancer_main([], fichier_contenu="0.76.1\n0\n", releases=[rel("v0.77.0", 10)]),
           "UNE ligne")


def main():
    tests = sorted((n, f) for n, f in globals().items() if n.startswith("test_") and callable(f))
    for nom, fonction in tests:
        try:
            fonction()
        except AssertionError as e:
            print(f"ECHEC {nom}: {e}")
            return 1
    print(f"OK: bump_trivy.py — {len(tests)} groupes de cas (choix, maturité, échecs de lecture, anonymat, reprises, "
          "idempotence, CI sans mirror-dhi, simulation)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
