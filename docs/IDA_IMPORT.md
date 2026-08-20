# Importer les métadonnées IDA

Pile ou Face importe les métadonnées utilisateur d’une base IDA, pas son désassemblage. Deux chemins produisent le même format canonique que l’import Ghidra, puis utilisent le même importeur conservateur.

## Export IDAPython — recommandé

Avec le binaire ouvert dans IDA, lancez **File > Script file…** et sélectionnez `tooling/export_to_pof.py`. Choisissez ensuite le fichier JSON de destination.

Dans VS Code, lancez **Pile ou Face: Importer depuis IDA/IDB…**, sélectionnez ce JSON puis exactement le binaire ouvert dans IDA. Le script exporte, selon les API disponibles, les noms et commentaires de fonctions, les prototypes, les commentaires d’adresses, les structs/enums, les variables locales Hex-Rays et les bookmarks historiques.

Les structs conservent de façon portable les noms, offsets et tailles des champs ; les types de champs IDA qui ne se traduisent pas sûrement sont dégradés en tableaux d’octets. Les variables locales sont présentes dans l’export pour préserver l’information, mais le stockage Host actuel ne les applique pas encore.

## Lecture directe `.idb` / `.i64` — best effort

La même commande accepte directement une base `.idb` ou `.i64`. Ce chemin utilise `python-idb` 0.8 en lecture seule et importe uniquement ce que son émulation IDAPython expose de manière fiable : les noms de fonctions et leurs commentaires regular/repeatable.

`python-idb` 0.8 annonce la prise en charge des bases IDA 5.0 à 7.6. Les prototypes, structs, variables locales et bookmarks ne sont pas garantis par ce chemin ; utilisez l’export IDAPython lorsqu’IDA est disponible. Une base illisible ou sans SHA-256 source exploitable produit une erreur sans écriture partielle.

## Sécurité et conflits

Le SHA-256 enregistré par IDA doit correspondre au binaire sélectionné. Toute différence interrompt l’import avant la première écriture.

Le rapport final distingue les éléments importés, inchangés, en conflit et dégradés. Relancer le même import est idempotent. Une annotation ou un type manuel, ou provenant d’un autre outil, reste prioritaire et n’est jamais écrasé.

La dépendance directe est [`python-idb`](https://github.com/williballenthin/python-idb), distribuée sous licence Apache-2.0. Aucun fichier IDB propriétaire n’est embarqué dans les tests : le parseur est couvert par une API synthétique et le chemin canonique par une fixture JSON.
