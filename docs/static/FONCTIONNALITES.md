# Fonctionnalites statiques

Ce document liste les fonctionnalites de la partie statique sous un angle presentation-projet : ce que fait la feature, pourquoi elle existe et quels fichiers l'implementent.

Pour un usage pratique, voir aussi [GUIDE_UTILISATION.md](GUIDE_UTILISATION.md), qui explique comment utiliser chaque vue et comment interpreter ses resultats.

## Vue globale

| Groupe | Objectif | Exemples de vues |
| --- | --- | --- |
| `CODE` | Lire et comprendre le programme | Desassemblage, CFG, Call Graph, Fonctions, Pseudo-C |
| `DATA` | Comprendre la structure du binaire | Strings, Symboles, Sections, Imports, Infos, Recherche |
| `AUDIT` | Auditer le code avec plugins dedies | Taint, Vulnerabilites |
| `MALWARE` | Detecter comportements suspects avec plugin | Behavior, Anti-analyse, YARA, CAPA |
| `OFFENSIF` | Exploitation et diff avance avec plugin | ROP, FLIRT, Diff |

## Lecture critique des features

Toutes les features ne donnent pas le meme niveau de preuve. Certaines sont des vues fiables sur les donnees du binaire, d'autres sont des heuristiques qui servent surtout a prioriser l'audit.

Important :

- le repo public garde les vues `CODE`, `DATA` et `Script` ;
- les vues `AUDIT`, `MALWARE` et `OFFENSIF` apparaissent dynamiquement quand un plugin compatible est installe et actif ;
- la carte `Options > Plugins` montre quels groupes optionnels sont effectivement disponibles.

| Feature | Maturite reelle | A presenter comme |
| --- | --- | --- |
| Desassemblage, Hex View, Strings, Symboles, Sections, Recherche | Solide pour l'inspection de base, depend de LIEF/Capstone et du format | Donnees d'analyse et navigation |
| Imports / Exports | Solide quand les tables existent, limite sur binaires stripped/statiques/obfusques | Surface API exposee ou consommee |
| Patch bytes / annotations / bookmarks | Fonctionnel et concret | Outillage d'edition et de prise de notes |
| CFG / Call Graph / Fonctions decouvertes | Heuristique avancee, bonne sur cas directs, plus fragile avec indirect calls, obfuscation, switch complexes ou ISA moins supportees | Aide a la comprehension du flux |
| Stack Frame / Calling Convention | Heuristique ABI-aware, meilleure avec frame pointer/DWARF, fragile avec optimisations fortes | Reconstruction probable de frame |
| Decompilateur | Depend fortement des outils externes disponibles (`ghidra`, `r2`, `retdec`) et de la qualite de leurs sorties | Pseudo-C d'aide a la lecture |
| Binary Diff / Similarite | Comparaison par symboles, blocs et MinHash ; utile mais pas preuve semantique | Similarite probable entre fonctions |
| Plugins optionnels (`AUDIT` / `MALWARE` / `OFFENSIF`) | Disponibilite depend du plugin installe, de sa licence et de ses outils | Enrichissements optionnels et signaux d'audit |

Important :

- les descriptions detaillees de `taint`, `vuln_patterns`, `behavior`, `anti-analyse`, `YARA`, `CAPA`, `ROP`, `FLIRT`, `deobfuscation` et `similarite` de fonctions correspondent maintenant a des plugins optionnels ;
- le host public garde leur place dans l'UI et dans le runtime, mais pas leur implementation metier.

## CODE

### Desassemblage

Le desassemblage transforme les octets de code en instructions assembleur lisibles. Il supporte la syntaxe Intel ou AT&T, la selection de section, les profils de blobs bruts et la navigation par adresse ou symbole.

Fichiers principaux :

- `backends/static/disasm.py`
- `backends/static/arch.py`
- `extension/src/static/hub.js`
- `extension/webview/static/panel-static.html`

Fonctionnalites visibles :

- ouverture d'un fichier `.asm`;
- mapping adresse vers ligne;
- navigation `main`, `_start`, `entry`;
- recherche par adresse ou symbole;
- annotations inline;
- bookmarks;
- xrefs vers et depuis une adresse;
- export du desassemblage.

### CFG

Le CFG, ou Control Flow Graph, represente le flux de controle d'une fonction ou d'un ensemble de blocs. Il aide a comprendre les conditions, boucles, retours et chemins de branchement.

Fichiers principaux :

- `backends/static/cfg.py`
- `extension/webview/shared/cfgHelpers.js`
- `extension/webview/hub.js`

Fonctionnalites visibles :

- mode tableau;
- mode graphique;
- recherche;
- fit automatique;
- export SVG;
- navigation vers le desassemblage.

### Call Graph

Le call graph represente les appels entre fonctions. Il sert a identifier les fonctions centrales, les wrappers, les points d'entree et les dependances.

Fichiers principaux :

- `backends/static/call_graph.py`
- `backends/static/xrefs.py`
- `extension/webview/shared/cfgHelpers.js`

Fonctionnalites visibles :

- graphe interactif;
- mode tableau;
- recherche;
- export SVG;
- clic sur une fonction pour naviguer.

### Fonctions

La liste des fonctions combine symboles, decouverte automatique et convention d'appel. Elle est utile sur les binaires strippes ou optimises.

Fichiers principaux :

- `backends/static/discover_functions.py`
- `backends/static/symbols.py`
- `backends/static/calling_convention.py`

Fonctionnalites visibles :

- adresse;
- nom;
- taille;
- type;
- score de confiance;
- convention d'appel;
- filtre de recherche;
- pivot vers desassemblage, CFG ou pseudo-C.

### Decompilateur

Le decompilateur produit du pseudo-C pour lire plus vite la logique haut niveau. Il peut utiliser plusieurs backends selon les outils disponibles.

Fichiers principaux :

- `backends/static/decompile.py`
- `backends/static/ghidra_decompile.py`
- `extension/src/static/staticHandlers.js`

Fonctionnalites visibles :

- choix du backend disponible;
- mode rapide ou precision;
- mode rapide : privilegie une reponse courte et exploitable vite, en essayant d'abord les backends les plus reactifs ou les plus lisibles pour un premier triage;
- mode precision : privilegie la fidelite au binaire, au flux de controle et aux appels observes, quitte a garder un pseudo-C moins propre mais plus proche de la realite;
  Ce mode ne "sait" pas la verite absolue, mais il score les sorties candidates contre des indices extraits du binaire lui-meme.
  Pour une fonction cible, le backend calcule d'abord les appels atteignables depuis cette fonction a partir du desassemblage et des symboles connus.
  Ensuite chaque sortie pseudo-C est notee selon plusieurs signaux :
  - appels presentes ou absents par rapport aux appels attendus ;
  - presence de structures de controle plausibles (`if`, `switch`, `while`, `return`) ;
  - presence d'indices de type utiles ;
  - penalite si la sortie contient trop de placeholders (`var_x`, `DAT_x`, `LAB_x`) ;
  - penalite si la sortie reste trop bas niveau (`goto`, artefacts proches de l'assembleur, warnings du decompilateur).
  En mode precision, les appels manquants sont plus fortement penalises et les appels bien retrouves sont plus fortement recompenses qu'en mode rapide.
  L'idee est donc de preferer une sortie parfois un peu plus brute, mais qui conserve mieux les appels et le flux reellement vus dans le binaire.
- selection de fonction;
- historique precedent/suivant;
- recherche dans le pseudo-C;
- enrichissement par annotations et stack frame.

### Hex View et patchs

La Hex View permet de lire les octets, verifier les offsets et appliquer des patchs simples.

Fichiers principaux :

- `backends/static/hex_view.py`
- `backends/static/patch_manager.py`
- `backends/static/binary_patch.py`

Fonctionnalites visibles :

- navigation par offset;
- longueur configurable;
- legende des sections;
- selection d'octets;
- ouverture de la selection dans le desassemblage;
- patch de bytes;
- undo/redo;
- liste des patchs persistants.

### Stack Frame

La stack frame expose les arguments et variables locales detectes dans une fonction. Elle aide a comprendre les acces a la pile.

Fichiers principaux :

- `backends/static/stack_frame.py`
- `backends/static/dwarf.py`
- `backends/static/decompile.py`

Fonctionnalites visibles :

- taille de frame;
- arguments;
- variables locales;
- noms `var_N` ou noms enrichis;
- propagation vers desassemblage, xrefs et pseudo-C.

### Binary Diff

Le Binary Diff compare deux binaires et classe les fonctions ajoutees, supprimees, modifiees ou similaires.

Implementation :

- plugin `OFFENSIF`
- commandes runtime attendues : `offensive.bindiff.run`, `offensive.func_similarity.run`

Fonctionnalites visibles :

- selection de deux binaires;
- seuil de similarite;
- statistiques de comparaison;
- liste des fonctions differentes.

## DATA

### Strings

Extrait les chaines lisibles et les rattache a un offset, une adresse virtuelle et une section quand possible.

Fichier principal : `backends/static/strings.py`

Options visibles :

- encodage auto, UTF-8, UTF-16 LE, UTF-16 BE;
- longueur minimale;
- filtre par section;
- export JSON ou CSV.

### Symboles

Liste les symboles du binaire : fonctions, variables, symboles externes ou definis.

Fichier principal : `backends/static/symbols.py`

Usages :

- trouver `main`;
- enrichir le desassemblage;
- nommer les noeuds du CFG et du call graph;
- naviguer vers une adresse.

### Sections

Expose les sections du binaire avec leur taille, offset, adresse virtuelle et parfois entropie.

Fichiers principaux :

- `backends/static/sections.py`
- `backends/static/entropy.py`

Usages :

- reperer `.text`, `.data`, `.rodata`, `.rsrc`;
- detecter des zones suspectes;
- filtrer strings et recherche;
- ouvrir le desassemblage d'une section precise.

### Imports et exports

Les imports montrent les API appelees par le binaire. Les exports montrent les fonctions exposees, notamment sur DLL ou bibliotheques.

Fichiers principaux :

- `backends/static/imports_analysis.py`
- `backends/static/import_xrefs.py`
- `backends/static/binary_exports.py`

Fonctionnalites visibles :

- groupement par DLL ou bibliotheque;
- badges de suspicion;
- callsites par import;
- navigation vers le desassemblage;
- exports demangles quand possible.

### Infos binaire

Resume les metadonnees du fichier.

Fichiers principaux :

- `backends/static/binary/headers.py`
- `backends/static/binary/entropy.py`
- `backends/static/binary/packer_signatures.yar`

Informations typiques :

- format ELF, PE, Mach-O ou RAW;
- architecture;
- mode 32/64 bits;
- entry point;
- interpreter;
- hashes MD5/SHA-256;
- imphash PE;
- detection de packers (heuristiques + signatures YARA formelles : UPX PE/ELF, ASPack, MPRESS, Petite, PECompact).

### Recherche binaire

Permet de chercher dans les octets du binaire.

Fichier principal : `backends/static/search.py`

Modes :

- texte;
- hex;
- regex;
- filtres offset min/max;
- sensibilite a la casse;
- export CSV/JSON.

### Ressources PE

Analyse les ressources embarquees des executables Windows.

Fichier principal : `backends/static/pe_resources.py`

Exemples :

- icones;
- manifests;
- versions;
- ressources arbitraires.

### Exceptions

Expose les donnees de gestion d'exceptions quand elles sont disponibles.

Fichier principal : `backends/static/exception_handlers.py`

Interet :

- comprendre du controle de flux indirect;
- reperer des handlers;
- mieux analyser certains binaires C++ ou Windows.

### Donnees typees

Interprete les octets d'une section comme types simples ou structures C.

Fichiers principaux :

- `backends/static/typed_data.py`
- `backends/static/structs.py`
- `backends/static/typed_struct_refs.py`

Fonctionnalites visibles :

- types `u8`, `u16`, `u32`, `u64`, `f32`, `f64`, string, ptr;
- edition de structs, unions et enums;
- application d'un type a un offset ou une adresse;
- persistance des types appliques;
- propagation vers d'autres vues.

## MALWARE

### Comportement

Produit une synthese d'indicateurs comportementaux.

Implementation :

- plugin `MALWARE` via `malware.behavior.run`
- exposition MCP possible via `plugin.malware.behavior.run`
- le host public garde l'invocation runtime et l'affichage de la vue

Exemples d'indicateurs :

- reseau;
- fichiers;
- processus;
- registre Windows;
- crypto;
- persistence;
- commandes shell.

### Taint

Suit les flux de donnees entre sources et sinks.

Implementation :

- plugin `AUDIT` via `audit.taint.run`
- exposition MCP possible via `plugin.audit.taint.run`
- le host public garde l'invocation runtime et l'affichage de la vue

Interet :

- detecter une entree utilisateur qui atteint une fonction dangereuse;
- expliquer un chemin de propagation;
- prioriser une analyse de vulnerabilite.

### Anti-analyse

Detecte les techniques qui tentent de gener l'analyse.

Implementation : plugin `MALWARE` via `malware.anti_analysis.run`

Exemples :

- anti-debug;
- anti-VM;
- timing checks;
- obfuscation;
- API suspectes.

### Detection YARA et CAPA

YARA sert a matcher des signatures. CAPA sert a identifier des capacites comportementales.

Implementation :

- plugin `MALWARE` via `malware.yara.run`
- plugin `MALWARE` via `malware.capa.run`
- le host public garde seulement le chargement des plugins et l'affichage des resultats

Fonctionnalites visibles :

- scan YARA;
- scan CAPA;
- filtre des resultats;
- export JSON;
- gestionnaire de regles;
- activation/desactivation de regles.

## OFFENSIF

### ROP Gadgets

Recherche des sequences d'instructions utilisables dans une chaine ROP.

Implementation : plugin `OFFENSIF` via `offensive.rop.run`

Resultats typiques :

- adresse du gadget;
- instructions;
- type de fin;
- architecture.

### Vulnerabilites

Detecte des APIs et patterns dangereux. Cette vue ne prouve pas qu'une vulnerabilite est exploitable : la presence de `strcpy` ou `system` est un signal d'audit, pas une confirmation.

Implementation : plugin `AUDIT` via `audit.vulns.run`

Exemples :

- `gets`;
- `strcpy`;
- `sprintf`;
- `system`;
- categories CWE;
- severite indicative.

Limites :

- faux positifs possibles si l'API est appelee avec une source constante ou controlee;
- faux negatifs possibles si la vulnerabilite est implementee sans API connue;
- doit etre croise avec `taint`, `call_graph`, `xrefs`, `decompile` ou la trace dynamique.

### FLIRT

Identifie des fonctions connues par signatures.

Implementation : plugin `OFFENSIF` via `offensive.flirt.run`

Interet :

- reconnaitre des fonctions de bibliotheques;
- eviter de perdre du temps sur du code standard;
- renommer automatiquement des fonctions connues.

### Deobfuscation

Tente de recuperer des chaines obfusquees.

Implementation : plugin `MALWARE` via `malware.deobfuscate.run`

Techniques :

- XOR mono-octet;
- XOR multi-octets;
- ROT;
- Base64;
- stackstrings x86-64 et ARM64.

## Analyse croisee (Investigation mode)

Vue d'enquête qui agrège les signaux de tous les plugins actifs et les regroupe par fonction puis par technique MITRE ATT&CK.

Implementation : plugin `cross-analysis-pro` via `croisee.cross_analyze.run`

### Classement par fonction

Chaque fonction connue du binaire reçoit un score combiné calculé à partir des `proof_dossiers` fournis par les plugins actifs (`taint`, `behavior`, `vulns`, `yara`, etc.).

Champs retournés par fonction :

- `function` — nom ou adresse;
- `combined_score` — score agrégé;
- `risk_level` — `HIGH` / `MEDIUM` / `LOW`;
- `signals` — liste des plugins qui ont contribué;
- `proof_dossiers` — preuves brutes par plugin;
- `summary` — résumé textuel.

### Clustering ATT&CK (v2)

Si le plugin `malware-triage-pro` est disponible, les techniques MITRE ATT&CK détectées deviennent le pivot principal de la vue.

Champs par technique :

- `id` — identifiant MITRE (ex. `T1055`);
- `name` — nom de la technique;
- `tactics` — liste de tactiques associées;
- `confidence` — `high` / `medium` / `low`;
- `patch_priority` — `true` si au moins une fonction liée cumule les signaux `taint` et `behavior`;
- `functions` — liste des fonctions correspondantes.

Si `malware-triage-pro` est absent ou si aucune technique ne matche : `techniques: []`, la section est masquée dans l'UI (rétrocompatibilité v1 totale).

### Schema JSON de sortie

```json
{
  "ranked_functions": [...],
  "techniques": [
    {
      "id": "T1055",
      "name": "Process Injection",
      "tactics": ["defense-evasion"],
      "confidence": "high",
      "patch_priority": true,
      "functions": ["sub_4010a0"]
    }
  ],
  "coverage": {"plugins_used": [...], "plugins_missing": [...]},
  "plugin_scoring": false
}
```

### Script Python

Le scripting integre permet d'automatiser l'analyse avec des imports directs vers les modules publics `backends.static.*`.

Fichiers principaux :

- `backends/static/repl/repl.py`
- `extension/webview/static/panel-static.html`

Exemple :

```python
from backends.static.binary.symbols import extract_symbols
from backends.static.search.strings import extract_strings

for s in extract_symbols(binary)[:10]:
    print(s["addr"], s["name"])

for item in extract_strings(binary)[:10]:
    print(item.get("offset"), item.get("value"))
```
