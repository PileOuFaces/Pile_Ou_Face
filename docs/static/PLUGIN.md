# Plugins

> **Créer un plugin ?** Lire [`PLUGIN_DEV.md`](PLUGIN_DEV.md) — guide complet pour la communauté.

Ce document definit la partie **host open source** pour integrer des plugins externes.

Le but ici n'est pas d'embarquer la logique metier specifique aux plugins.
Le but est de permettre a ce repo de :
- detecter des plugins externes ;
- verifier leurs manifests ;
- les attacher proprement ;
- survivre si aucun plugin n'est installe ;
- survivre si un plugin est invalide ou casse.

## Split recommande

### Dans ce repo open source
- runtime plugin minimal ;
- schema manifest ;
- registry et discovery ;
- hooks backend/UI/export ;
- decompilation de base ;
- integration avec l'UI.

### Plugins externes
- analyses optionnelles ;
- donnees et regles propres au plugin ;
- ressources de build ;
- securisation des artefacts.

## Contrainte importante

La partie `MALWARE` n'est pas garantie.

Donc les fonctions qui dependent de :
- `taint`
- `behavior`
- `anti_analysis`

doivent etre traitees comme **optionnelles** cote host.

En revanche, la decompilation reste dans le package de base et peut etre consideree comme une capacite `core`.

## Principes du host

1. `No plugin, no problem`
Le produit doit rester utilisable sans plugin.

2. `Fail closed for plugin, fail open for host`
Si un plugin echoue, le host continue sans lui.

3. `Contract first`
Le manifest et le format des hooks doivent rester stables.

4. `No domain plugin logic in host`
Le host integre, mais ne porte pas la logique commerciale.

## Emplacement de recherche

Dans l'extension VS Code, les plugins sont installes et charges depuis le
`storageUri` du workspace :

```text
<workspaceStorage>/<workspace-id>/PileOuFaces.stack-visualizer/plugins/
```

Pour les tests CLI hors VS Code, la recherche peut etre forcee explicitement avec
`$POF_PLUGIN_PATH`.

## Structure attendue d'un plugin installe

Aujourd'hui, le host public attend un plugin **deja extrait** dans un dossier.

Exemple :

```text
<workspaceStorage>/<workspace-id>/PileOuFaces.stack-visualizer/plugins/
└── acme.my-analysis-plugin/
    ├── manifest.json
    ├── python/
    │   └── plugin_main.py
    ├── data/
    └── metadata/
```

Points importants :

- le fichier attendu par le host s'appelle `manifest.json` ;
- le point d'entree Python est charge depuis `python/` ;
- le repo public ne gere pas encore l'installation automatique d'un bundle chiffre ;
- un artefact plugin (`.pofplug` ou autre) doit pour l'instant etre extrait dans un dossier lisible par le runtime du host.

## Installation manuelle pour les tests

Pour tester un plugin localement dans le host public :

1. builder le plugin ;
2. installer le bundle via `Options > Plugins > Installer…` pour qu'il soit extrait dans `context.storageUri/plugins/<plugin-id>/` ;
3. verifier qu'il contient bien `manifest.json` et `python/plugin_main.py` ;
4. lancer :

```bash
BINHOST_PLUGIN_PATH="<workspaceStorage>/<workspace-id>/PileOuFaces.stack-visualizer/plugins" \
  python -m backends.plugins.runtime list --attach
```

Si tout va bien :

- le plugin passe a l'etat `active` ;
- ses commandes apparaissent dans le snapshot runtime ;
- l'UI peut afficher `AUDIT`, `MALWARE` ou `OFFENSIF` si les capabilities correspondantes sont presentes.

## Installation via l'UI

Le host public sait maintenant installer un plugin depuis `Options > Plugins`.

Flux :

1. cliquer sur `Installer…` ;
2. selectionner soit :
   - un bundle `.pofplug` ;
   - un dossier plugin deja extrait avec `manifest.json` ;
3. laisser le host copier ou extraire le plugin dans `context.storageUri/plugins/` ;
4. l'etat runtime est rafraichi automatiquement.

Le bouton `Ouvrir dossier plugins` pointe lui aussi vers `context.storageUri/plugins/`.

Le host public sait aussi maintenant importer une licence depuis `Options > Plugins > Importer licence…`.
Les fichiers de licence sont copies dans :

```text
~/.pile-ou-face/licenses/
```

Le front de l'extension scanne uniquement `context.storageUri/plugins/`. Pour un test runtime hors VS Code, utiliser `BINHOST_PLUGIN_PATH` vers le dossier de plugins a tester.

Limitations actuelles :

- pas encore de saisie manuelle d'une cle courte ;
- pas encore de compilation/obfuscation dure cote host ;
- pas encore de revocation ou activation en ligne.

## Manifest minimal

Exemple :

```json
{
  "id": "acme.my-analysis-plugin",
  "name": "My Analysis Plugin",
  "version": "1.0.0",
  "kind": "analysis-pack",
  "host": {
    "api_version": 1,
    "min_version": "0.1.0",
    "max_version": "0.1.x"
  },
  "ui": {
    "family": "audit"
  },
  "distribution": {
    "encrypted": false,
    "bundle_format": "directory"
  },
  "licensing": {
    "required": false,
    "mode": "",
    "status": "unlocked",
    "message": ""
  },
  "entrypoints": {
    "python": {
      "module": "plugin_main",
      "register": "register_plugin"
    }
  },
  "capabilities": {
    "analysis": ["my_feature.enrich"]
  }
}
```

## Champ `ui.family`

Le champ `ui` permet au plugin de se déclarer dans un groupe UI du host.

```json
{
  "ui": {
    "family": "audit"
  }
}
```

- `family` : nom du groupe UI auquel ce plugin contribue (`audit`, `malware`, `offensif`, ou toute valeur custom)
- Si `family` est renseigné et que le plugin est actif, le host affiche le groupe correspondant
- Si le champ est absent, le plugin reste fonctionnel mais n'active aucun groupe UI optionnel

## Champs `distribution` et `licensing`

Le host public sait deja lire ces champs dans le manifest.

### `distribution`

Exemple :

```json
{
  "distribution": {
    "encrypted": true,
    "bundle_format": "pofplug"
  }
}
```

Usage :

- `encrypted: true` permet au host d'afficher qu'un plugin est chiffre ;
- `bundle_format` permet d'indiquer le format de distribution attendu.

### `licensing`

Exemple :

```json
{
  "licensing": {
    "required": true,
    "mode": "signed-license",
    "status": "locked",
    "message": "Licence requise pour activer ce plugin",
    "public_key_path": "keys/license-public.pem",
    "license_filename": "acme.my-analysis-plugin.license.json",
    "machine_bound": true
  }
}
```

Usage :

- `required` dit si le plugin attend une licence ;
- `mode` decrit le mecanisme attendu (`signed-license`, `license-file`, etc.) ;
- `status` permet au plugin de remonter un etat comme `locked`, `unlocked`, `expired` ;
- `message` permet d'afficher un diagnostic lisible dans l'UI du host.
- `public_key` ou `public_key_path` fournit la cle publique servant a verifier la signature ;
- `license_filename` permet de fixer le nom du fichier attendu dans `~/.pile-ou-face/licenses/` ;
- `machine_bound` impose que la licence corresponde a l'identifiant machine courant.

## Ce que le host sait deja faire

Le host public sait deja :

- lire `distribution.encrypted` ;
- lire `licensing.required`, `licensing.mode`, `licensing.status`, `licensing.message` ;
- verifier une licence JSON signee avec une cle publique fournie par le plugin ;
- installer un bundle `.pofplug` chiffre si la licence signee correspond a la machine ;
- conserver le plugin chiffre au repos dans `context.storageUri/plugins/` ;
- ne dechiffrer le payload du plugin qu'au moment de l'attachement runtime ;
- bloquer l'attachement d'un plugin tant que la licence est absente, invalide, expiree ou liee a une autre machine ;
- importer une licence depuis l'UI vers `~/.pile-ou-face/licenses/` ;
- exposer l'identifiant machine courant via `python3 backends/plugins/runtime.py machine-id` ;
- afficher ces informations dans `Options > Plugins` ;
- compter les plugins verrouilles ;
- masquer les groupes UI optionnels tant qu'un plugin compatible n'est pas actif.

## Ce qui n'est pas encore fait

Le host public **n'implemente pas encore** :

- la saisie d'une cle courte a convertir en licence ;
- l'installation automatique d'un artefact chiffre ;
- l'activation en ligne ou la revocation distante d'une licence.

Ces etapes doivent etre branchees plus tard sans casser le contrat du host public.

## Runtime actuel du host

Le socle MVP est maintenant dans :

```text
backends/plugins/
├── __init__.py
├── install_license.py
├── license.py
├── manifest.py
├── registry.py
└── runtime.py
```

### Capacites deja posees
- validation stricte de `manifest.json` ;
- discovery de plugins locaux ;
- registry des etats `active` / `disabled` / `invalid` / `incompatible` / `failed` ;
- etat `locked` pour les plugins sans licence valide ;
- attachement Python avec `register_plugin(context)` ;
- contexte minimal avec `register_analysis_enricher`, `register_ui_panel`, `register_exporter`, `register_command` ;
- CLI admin pour `list`, `inspect`, `validate`, `invoke`, `machine-id` ;
- panneau `Options > Plugins` dans l'UI pour voir les plugins charges, les dossiers surveilles, installer un plugin, importer une licence et ouvrir les dossiers du `storageUri` ;
- placeholders host pour l'etat `encrypted` / `license required` / `locked`, afin que le vrai deverrouillage par cle puisse etre branche plus tard sans changer l'UI publique ;
- pont MCP generique vers les plugins actifs via `plugins_list` et `plugin_invoke`.

## Commandes utiles

```bash
python -m backends.plugins.runtime list
python -m backends.plugins.runtime list --attach
python -m backends.plugins.runtime inspect acme.my-analysis-plugin
python -m backends.plugins.runtime validate /path/to/plugin
python -m backends.plugins.runtime invoke audit.vulns.run --payload-json '{"binaryPath":"examples/test.elf"}'
```

## UI host

Le repo public expose maintenant un espace `Plugins` dans `Options` pour :

- lister les plugins detectes ;
- voir leur etat (`active`, `disabled`, `invalid`, etc.) ;
- afficher leurs capabilities et commandes attachees ;
- montrer les dossiers surveilles par le runtime ;
- ouvrir rapidement `context.storageUri/plugins/`.

Cet espace sert aussi de zone de diagnostic pour verifier rapidement :

- si un plugin a bien ete detecte ;
- s'il est compatible avec la version du host ;
- s'il est chiffre ;
- si une licence est requise ;
- quelles commandes ont ete attachees reellement au runtime.

Quand les bundles chiffres et la verification de cle seront branches, le host affichera aussi :

- plugin chiffre ou non ;
- licence requise ou non ;
- statut attendu (`locked`, `unlocked`, `expired`, etc.) ;
- message de diagnostic renvoye par le plugin.

## MCP et plugins

Le MCP public n'expose plus directement les capacites retirees du host.
A la place, il donne acces aux plugins actifs via deux outils generiques :

- `plugins_list` : liste l'etat runtime, les manifests, les capabilities et les commandes exposees ;
- `plugin_invoke` : execute une commande plugin active, par exemple `audit.vulns.run`.

Quand un plugin est attache, ses commandes peuvent aussi apparaitre directement dans `tools/list` sous des noms dynamiques comme `plugin.audit.vulns.run` ou `plugin.malware.behavior.run`.

Le pattern attendu cote client MCP est donc :

1. appeler `plugins_list` ;
2. verifier qu'un plugin actif expose bien la commande voulue ;
3. appeler `plugin_invoke`.

Exemple :

```json
{
  "command": "audit.vulns.run",
  "payload": {
    "binaryPath": "/abs/path/sample.elf"
  }
}
```

Quand un plugin est verrouille ou absent :

- `plugins_list` permet de voir qu'il est `locked`, `invalid`, `failed` ou non detecte ;
- `plugin_invoke` doit echouer proprement ;
- le MCP ne doit pas annoncer les outils dynamiques `plugin.*` si le plugin n'est pas actif.

Quand un plugin est actif :

- ses commandes peuvent apparaitre dans `tools/list` ;
- un client MCP peut appeler directement `plugin.audit.vulns.run`, `plugin.malware.behavior.run`, `plugin.offensive.rop.run`, etc. ;
- le host public reste seulement un pont d'execution, pas le porteur de la logique metier du plugin.

## Regle de split pour `vuln_patterns`

### Core
- imports ;
- xrefs ;
- call graph ;
- decompilation ;
- proof dossiers ;
- scoring de base ;
- format JSON stable.

### Optionnel
- `taint` ;
- `behavior` ;
- `anti_analysis` ;
- enrichers optionnels.

Les petits helpers neutres peuvent etre factorises dans le core.
Les helpers purement malware peuvent etre dedoubles sans probleme si cela evite un mauvais couplage.

## Etat actuel

Le host public est maintenant centre sur :

- la detection et l'attachement des plugins ;
- l'exposition UI dans `Options > Plugins` ;
- l'invocation runtime depuis l'extension ;
- l'exposition MCP via `plugins_list`, `plugin_invoke` et les outils dynamiques `plugin.*`.

La logique metier specifique aux plugins ne doit pas vivre dans le host public.
