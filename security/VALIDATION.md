# Validation locale — 2026-09-27

Lot limité à Gitleaks bloquant et aux preuves de publication. Aucun plugin premium modifié.

## Réussites

- Gitleaks 8.30.1 `git --log-opts=HEAD --redact=100 --config .gitleaks.toml` : 571 commits, aucune détection restante. Sept faux positifs historiques vérifiés, exclus uniquement par couple commit/chemin ; expiration 2026-12-20.
- `python3 -m tooling.security_baseline` : valide.
- `python3 -m pytest tooling/tests/test_security_baseline.py tooling/tests/test_security_scanners.py -q` : 9 tests réussis.
- `actionlint .github/workflows/gitleaks.yml .github/workflows/publish.yml` : réussi.
- `npm ci`, profil officiel, configuration officielle puis `npx vsce package --out /private/tmp/pof-security-release.vsix` : réussi, 297 fichiers, environ 2,5 Mo ; typecheck et compilation inclus.
- Extraction du VSIX puis `anchore/syft:v1.30.0 dir:/workspace -o cyclonedx-json=/workspace/pile-ou-face.cdx.json` : réussi.
- `npm test -- --reporter dot` : 969 réussis, 1 pending, après restauration du manifeste OSS modifié par le packaging officiel. Le premier lancement sur le manifeste officiel avait deux échecs de tests réservés au profil OSS.
- `npm audit --omit=dev --audit-level=moderate` : aucune vulnérabilité.

## Limites et travaux restants

- `npm ci` signale 13 vulnérabilités de développement (4 moderate, 9 high), non corrigées dans ce lot ; pas de `audit fix --force`.
- Trivy config des images de compilation : trois HIGH AVD-DS-0002 (gcc-multiarch, go, rust exécutés en root). Le workflow Trivy reste informatif ; le durcissement et les scans des images réelles restent à traiter.
- `actionlint` global signale trois erreurs préexistantes dans docker-decompilers.yml (option vide, SC2086, condition multiligne). Les workflows modifiés passent.
- Attestations GitHub, dépôt SARIF et publication Marketplace/Open VSX non exécutés localement. Aucun paquet publié et aucun déploiement effectué.
- Marketplace dépend désormais du succès Open VSX et réutilise son artefact exact. Une panne Open VSX bloque donc aussi Marketplace : validation humaine requise pour ce choix.
- Suite complète Python/E2E/matrice multiplateforme non rejouée : ce rapport ne constitue pas le repli CI complet exigé avant merge.
- GitNexus : impact nul sur les fonctions applicatives du host ; seule la date du test de gouvernance change.

PR à conserver en brouillon tant que la validation de publication et la revue humaine ne sont pas obtenues.
