# Télémétrie d’usage

Pile ou Face mesure des catégories d’usage agrégées afin de savoir quelles
fonctions sont utilisées et si Run Trace aboutit. La télémétrie ne mesure jamais
le contenu analysé. Le registre exécutable
[`telemetryEvents.ts`](../../extension/src/shared/telemetry/telemetryEvents.ts)
est l’allowlist V1 faisant autorité.

## Activation et destination

Un événement n’est envoyé que si toutes les conditions suivantes sont réunies :

1. la télémétrie globale de VS Code est activée ;
2. `pileOuFace.telemetry.enabled` vaut `true` ;
3. le build contient une URL HTTPS de provider dans `telemetryProviderUrl`.

Le dépôt open source laisse cette URL vide : un build effectué directement
depuis le dépôt n’a donc aucune destination et n’émet aucun trafic de
télémétrie. Un build officiel ou un self-hoster peut fournir son propre endpoint
via l’overlay non versionné `product.json`. Le client ne contacte pas directement
Azure Application Insights et n’embarque ni secret, ni token, ni connection
string.

La désactivation du réglage global VS Code ou de
`pileOuFace.telemetry.enabled` interrompt aussi les requêtes déjà en vol. Il n’y
a ni fallback, ni retry, ni file d’attente persistante.

## Registre V1

Chaque événement exige exactement les propriétés indiquées. Toute propriété
inconnue, manquante, d’un mauvais type ou hors enum entraîne le rejet de
l’événement complet.

| Événement | Propriétés autorisées |
| --- | --- |
| `extension.activated` | `extensionVersion`, `vscodeVersionMajor`, `platform` (`windows`, `linux`, `macos`, `other`) |
| `hub.opened` | `state` (`created`, `revealed`), `initialPanel` |
| `panel.opened` | `panel` (`dashboard`, `static`, `dynamic`, `runtime`, `tools`, `settings`) |
| `binary.loaded` | `binaryFormat` (`elf`, `pe`, `macho`, `raw`, `unknown`), `arch` (`x86`, `x64`, `arm`, `arm64`, `other`, `unknown`) |
| `static.feature.used` | `feature` (`disassembly`, `functions`, `cfg`, `call_graph`, `decompiler`, `stack_frame`, `hex`, `script`, `binary_info`, `sections`, `imports`, `symbols`, `strings`, `typed_data`, `search`, `pe_resources`, `exceptions`) |
| `static.interface_mode.changed` | `mode` (`simple`, `advanced`) |
| `payload.mode.used` | `payloadMode` (`builder`, `file`, `pwntools`, `exploit_helper`) |
| `payload.builder_level.changed` | `level` (`beginner`, `advanced`) |
| `dynamic.run_trace.started` | `arch`, `payloadMode`, `target` (`stdin`, `argv1`, `both`, `file`, `auto`), `sourceProvided` (booléen) |
| `dynamic.run_trace.completed` | `payloadMode`, `durationBucket` (`<1s`, `1-5s`, `5-15s`, `15-60s`, `>60s`), `crashDetected` (booléen) |
| `dynamic.run_trace.failed` | `payloadMode`, `durationBucket`, `errorCategory` (`invalid_input`, `unsupported_binary`, `compilation_failed`, `backend_failed`, `timeout`, `unknown`) |
| `dynamic.visualizer.opened` | `origin` (`fresh_run`, `history`), `surface` (`embedded`, `standalone`) |
| `dynamic.stack_mode.changed` | `stackMode` (`simple`, `expert`, `advanced`), `surface` (`embedded`, `standalone`) |

Il n’existe pas d’événement `dynamic.history.opened` en V1. L’usage réel de
l’historique est compté uniquement lorsqu’il ouvre effectivement le visualiseur,
avec `dynamic.visualizer.opened` et `origin: history`.

Une trace annulée ou devenue obsolète conserve localement le résultat
`cancelled`, mais n’émet aucun événement terminal. Elle apparaît donc comme la
différence entre les compteurs `started`, `completed` et `failed`, sans gonfler
le taux d’échec réel.

## Données interdites

La télémétrie refuse notamment : chemins et noms de fichiers, workspace,
identité ou identifiant de machine, contenu ou hash de binaire, source,
désassemblage, symboles ou fonctions utilisateur, payload et preview, script
Pwntools, stdin/argv, recherche, annotations, adresses, registres, stack, heap,
mémoire, trace, stdout/stderr, message d’erreur et stack trace bruts.

Aucun identifiant utilisateur, machine ou session n’est créé. L’enveloppe réseau
contient uniquement `schemaVersion`, `eventName` et les propriétés allowlistées.
Le body est limité à 4 Kio.

## Transport et rétention

Les envois sont asynchrones, best effort, limités à quatre requêtes simultanées
et abandonnés après 1,5 seconde. Une panne réseau n’affecte jamais une opération
Pile ou Face et n’affiche aucune erreur utilisateur.

Le client ne conserve aucun événement. Le provider V1 ne doit pas journaliser
les bodies bruts ; il doit revalider le même registre, appliquer un rate limit
et définir une durée de rétention finie pour les seules métriques agrégées avant
d’être activé. Tant que cette politique serveur n’est pas configurée et publiée,
`telemetryProviderUrl` doit rester vide.

## Ajouter ou modifier un événement

Une évolution doit rester un changement de registre explicite et revu :

1. justifier la métrique produit sans donnée utilisateur ;
2. utiliser uniquement des booléens ou des enums finis, et bucketiser les
   mesures numériques ;
3. modifier `telemetryEvents.ts` et ses tests de schéma avant
   l’instrumentation ;
4. ajouter les tests de consentement et de corpus sensible nécessaires ;
5. mettre à jour ce document et le validateur du provider ;
6. ne raccorder que la frontière métier concernée, jamais un collecteur global
   de clics ou d’erreurs.

Une propriété inconnue n’est jamais ajoutée dynamiquement et une erreur brute
n’est jamais passée à `trackFailure`.
