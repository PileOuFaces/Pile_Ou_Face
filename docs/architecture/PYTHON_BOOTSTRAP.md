# Préparation Python de l'extension (bootstrap)

## Portée et méthode

- Ce document décrit le comportement **actuel** de préparation Python de l'extension, au commit de base `0e96a4f75f8622009cce572262b105e1962b43e4`.
- Il provient **exclusivement de la lecture statique** de `extension/src/` et de `extension/backends/requirements.txt`. Rien n'a été exécuté : aucune activation de l'extension, aucune création de venv, aucune installation, aucun essai réseau.
- Tout comportement présenté comme « déduit » est une conclusion tirée de la lecture du code, **pas une observation d'exécution**.
- Les références `chemin:ligne` sont relatives à `extension/` et valables au commit de base.
- Hors périmètre de ce document : toute correction, consentement, verrouillage de versions ou retrait de `--break-system-packages`.

## 1. Déclencheurs de préparation Python

### 1.1 Point d'entrée unique

- La fonction de préparation est `ensurePythonDependencies`, définie en `src/shared/utils.ts:112` et exportée en `src/shared/utils.ts:398`.
- Hors tests, son seul appel dans `src/` est en `src/extension.ts:134` (import en `src/extension.ts:28`). Aucune commande ni aucun gestionnaire de webview ne l'appelle (recherche textuelle dans `src/`, tests exclus).

### 1.2 Chemin d'activation

- `activate(context)` est défini en `src/extension.ts:103` et exporté en `src/extension.ts:286-288`.
- Le bloc de préparation s'exécute pendant `activate`, après l'initialisation du stockage et du niveau de log (`src/extension.ts:129-137`), sous la condition qu'au moins un dossier de workspace soit ouvert : `if (folders && folders.length > 0)` (`src/extension.ts:130-131`).
- Sans dossier de workspace, la préparation n'est pas déclenchée (déduit de `src/extension.ts:131`).
- L'appel est fait sans `await` : la promesse est lancée puis son rejet éventuel est seulement journalisé (`src/extension.ts:134-136`). L'activation ne attend donc pas la fin de la préparation (déduit).
- Les événements qui provoquent l'activation de l'extension (par exemple `activationEvents`) sont déclarés hors de `extension/src/` et **ne peuvent pas être établis par cette lecture**.

### 1.3 Action utilisateur avant installation

- Aucune confirmation n'est demandée avant la création du venv ni avant l'installation : le code ne contient aucun appel de type boîte de dialogue, choix ou consentement sur ce chemin (`src/shared/utils.ts:112-182`).
- L'appel de démarrage passe `{ quiet: true }` (`src/extension.ts:134`). Le seul affichage utilisateur du chemin, `showWarningMessage`, est conditionné par `!quiet` (`src/shared/utils.ts:143-145` et `src/shared/utils.ts:176-180`). Au démarrage, aucun message visible n'est donc émis par cette fonction ; seules des lignes du canal de log le sont (déduit).
- Un commentaire indique que l'installation des décompilateurs est proposée à la demande via un menu déroulant (`src/extension.ts:139`). Ce commentaire concerne les décompilateurs, pas `requirements.txt`, et n'a pas été vérifié ici.

## 2. Sélection de l'exécutable Python

### 2.1 Au démarrage (préparation)

- L'exécutable est obtenu par `resolvePythonExecutable(root, context.globalState)` (`src/extension.ts`), qui lit `pythonPath` dans `pof-settings` puis délègue à `detectPythonExecutable(root, settingsPythonPath)` (`src/shared/utils.ts`). Le réglage utilisateur est donc pris en compte dès la préparation (#519).
- `detectPythonExecutable` (`src/shared/utils.ts:184-196`) :
  1. retourne `settingsPythonPath` s'il est renseigné (`src/shared/utils.ts:185`) ;
  2. sinon calcule `backendBase` = chemin de l'extension (`_extensionPath`) ou, s'il est vide, `path.resolve(root)` (`src/shared/utils.ts:186`) ;
  3. teste dans l'ordre `backends/.venv/bin/python3`, `backends/.venv/Scripts/python.exe`, `backends/.venv/Scripts/python` et retourne le premier qui existe (`src/shared/utils.ts:187-194`) ;
  4. sinon retourne la chaîne `'python3'` (`src/shared/utils.ts:195`).
- Le chemin de l'extension est renseigné par `setExtensionPath(context.extensionPath)` (`src/extension.ts:104`, `src/shared/utils.ts:34-36`).

### 2.2 À l'exécution des fonctionnalités

- Le point unique de résolution est `resolvePythonExecutable` (`src/shared/utils.ts`) : réglage `pythonPath` s'il est renseigné (chaîne non vide), sinon détection du venv puis `python3`. Il est utilisé par `src/extension.ts`, `src/shared/sharedHandlers.ts` (bridges annotations, historique de chat, historique de patchs et handlers IA) et `src/shared/staticCache.ts`. `src/static/hub.ts` passe `getConfiguredPythonPath(context.globalState)` au `detectPythonExecutable` injecté. `src/static/staticHandlers.ts:474` conserve sa lecture directe, équivalente. Sa valeur par défaut est la chaîne vide (`src/static/hub.ts:153`).
- `staticCache.ts` n'a pas accès au contexte VS Code : il lit le `globalState` enregistré à l'activation par `setSettingsStore(context.globalState)` (`src/extension.ts`).
- Un autre résolveur existe pour le décompilateur : `_findPythonExe` teste `backends/.venv/bin/python3`, `backends/.venv/bin/python`, puis `python3`, puis `python` (`src/static/decompilerCommands.ts:1061-1074`). La boucle retourne le premier candidat sans séparateur de chemin sans le tester, donc `python3` en pratique si aucun venv n'existe (déduit de `src/static/decompilerCommands.ts:1069-1072`).

## 3. Séquence de préparation, étape par étape

Toutes les références ci-dessous sont dans `src/shared/utils.ts`, fonction `ensurePythonDependencies` (lignes 112-182).

### 3.1 Vérification de `requirements.txt`

- `requirementsPath` = `<backendBase>/backends/requirements.txt` (`src/shared/utils.ts:114-115`).
- Si le fichier est absent : journal `[pip] requirements.txt introuvable.` puis retour, sans message visible et sans aucune autre action (`src/shared/utils.ts:116-119`).

### 3.2 Création de `backends/.venv`

- Condition : l'exécutable vaut exactement `'python3'` ou `'python'` (`src/shared/utils.ts:120`). Si `detectPythonExecutable` a trouvé un python de venv ou si un chemin a été fourni, cette étape est ignorée (déduit).
- Le venv est créé seulement si le dossier `<backendBase>/backends/.venv` n'existe pas (`src/shared/utils.ts:121-122`). Un dossier existant n'est ni vérifié ni recréé (déduit).
- Journal : `[venv] Création du venv…` (`src/shared/utils.ts:123`).
- Commande exacte : `cp.exec` avec la chaîne de shell `${pythonExe} -m venv ${venvPath}`, c'est-à-dire `python3 -m venv <backendBase>/backends/.venv` (ou `python`), sans guillemets autour du chemin (`src/shared/utils.ts:125-128`). L'exécution passe par un shell car il s'agit de `exec` et non de `execFile` (déduit).
- Après succès, le premier candidat existant parmi `bin/python3`, `Scripts/python.exe`, `Scripts/python` du venv devient `pythonExe`, avec le journal `[venv] Utilisation: <chemin>` (`src/shared/utils.ts:129-140`). Si aucun candidat n'existe, `pythonExe` reste `python3`/`python` (déduit de `src/shared/utils.ts:134-140`).

### 3.3 Test des dépendances de base

- Liste testée : `unicorn` et `capstone` uniquement (`src/shared/utils.ts:150`).
- Commande exacte pour chacune, via `cp.exec` : `${pythonExe} -c "import ${dep}"` (`src/shared/utils.ts:152-156`), dans l'ordre, avec arrêt au premier échec (`src/shared/utils.ts:157-160`).
- Si les deux imports réussissent : journal `[pip] Dépendances OK.` puis retour (`src/shared/utils.ts:162-165`).
- Les autres paquets de `requirements.txt` (`flare-capa`, `lief`, `python-idb`, `cryptography`, `yara-python`) ne sont pas testés. S'ils manquent alors que `unicorn` et `capstone` sont présents, aucune installation n'est lancée (déduit).

### 3.4 Installation depuis `requirements.txt`

- Journal : `[pip] Installation des dépendances…` (`src/shared/utils.ts:166`).
- Commande exacte, via `cp.execFile` (sans shell) : exécutable `pythonExe`, arguments, dans l'ordre : `-m`, `pip`, `install`, `-r`, `<requirementsPath>`, `--quiet`, `--break-system-packages` (`src/shared/utils.ts:169`).
- `--break-system-packages` est donc passé **systématiquement**, y compris quand `pythonExe` est le python du venv (`src/shared/utils.ts:169`). Le comportement de pip face à cet argument dans un venv n'est pas établissable par lecture.
- Aucune option `timeout` ni `maxBuffer` n'est fournie à `execFile` (`src/shared/utils.ts:169-171`) : aucune limite de durée n'est imposée par ce code (déduit).
- Aucune option d'index, de proxy, de contrainte ni `--require-hashes` n'apparaît dans les arguments (`src/shared/utils.ts:169`).
- Après succès : journal `[pip] Installation terminée.` (`src/shared/utils.ts:172`). Aucune vérification n'est refaite après installation (déduit de `src/shared/utils.ts:172-182`).

## 4. Versions et empreintes des dépendances

Contenu de `backends/requirements.txt` (7 lignes, sans commentaire) :

| Ligne | Spécification | Statut |
| --- | --- | --- |
| `backends/requirements.txt:1` | `unicorn==2.1.4` | Version figée |
| `backends/requirements.txt:2` | `capstone` | Non figée, aucune contrainte |
| `backends/requirements.txt:3` | `flare-capa` | Non figée, aucune contrainte |
| `backends/requirements.txt:4` | `lief` | Non figée, aucune contrainte |
| `backends/requirements.txt:5` | `python-idb>=0.8,<0.9` | Intervalle, non figée |
| `backends/requirements.txt:6` | `cryptography>=42.0.0` | Borne basse seulement |
| `backends/requirements.txt:7` | `yara-python` | Non figée, aucune contrainte |

- Les versions ne sont donc **pas** toutes figées : une seule dépendance sur sept l'est (`backends/requirements.txt:1`). Les dépendances transitives ne sont pas contraintes par ce fichier.
- **Aucune empreinte `--hash` n'est utilisée** : elle est absente du fichier (`backends/requirements.txt:1-7`) et l'option `--require-hashes` est absente de la commande pip (`src/shared/utils.ts:169`).
- Aucun fichier de verrouillage n'est référencé dans les sources lues.

## 5. Échecs, messages et poursuite

| Situation | Message de log | Message visible | Suite | Référence |
| --- | --- | --- | --- | --- |
| `requirements.txt` absent | `[pip] requirements.txt introuvable.` | Non | Retour, arrêt de la préparation | `src/shared/utils.ts:116-119` |
| Échec de `venv` | `[venv] Erreur: <stderr>` | `Impossible de créer backends/.venv: <message>` si `quiet` est faux | Retour, aucune installation tentée | `src/shared/utils.ts:141-147` |
| Un import de base échoue | Aucun message d'erreur | Non | Passage à l'installation | `src/shared/utils.ts:157-160` |
| Imports de base réussis | `[pip] Dépendances OK.` | Non | Retour, pas d'installation | `src/shared/utils.ts:162-165` |
| Échec de `pip install` | `[pip] Erreur: <stderr ou message>` | `Dépendances manquantes. Exécutez: <pythonExe> -m pip install -r requirements.txt` si `quiet` est faux | La fonction se termine normalement, sans relance ni nouvelle tentative | `src/shared/utils.ts:173-181` |
| Installation réussie | `[pip] Installation terminée.` | Non | Fin | `src/shared/utils.ts:172` |

- La préparation de démarrage utilise `quiet: true` (`src/extension.ts:134`) : les deux messages visibles du tableau ne sont donc **jamais affichés sur ce chemin**. Seules des lignes du canal de log sont écrites (déduit).
- Après un échec de `pip`, l'erreur est absorbée : la fonction ne relance pas l'exception, donc le `.catch` de `src/extension.ts:134-136` n'est pas atteint pour ce cas (déduit de `src/shared/utils.ts:173-181`). Ce `.catch` ne s'applique qu'à une exception inattendue, qu'il journalise sous `[Python setup] Warning: <message>` (`src/extension.ts:135`).
- Le message visible de `pip` suggère `... -m pip install -r requirements.txt` sans chemin complet de fichier ni `--break-system-packages` (`src/shared/utils.ts:178`).
- Aucun code de sortie n'est inspecté par code : `execFile` et `exec` rejettent sur toute erreur (`src/shared/utils.ts:126-127`, `src/shared/utils.ts:155`, `src/shared/utils.ts:169-170`). La distinction par code de retour n'existe donc pas dans le code lu : tout code non nul suit la même branche. Le message transmis est `stderr` s'il est non vide, sinon `error.message` pour pip (`src/shared/utils.ts:170`), et `stderr` seul pour la création du venv (`src/shared/utils.ts:127`).

### Cas de l'absence de réseau

- **Traitement d'erreur visible dans le code** : si `pip install` échoue pour cause réseau, la branche d'échec est la même que ci-dessus : journal `[pip] Erreur: …` avec le `stderr` de pip, et message d'avertissement seulement si `quiet` est faux (`src/shared/utils.ts:173-181`). Au démarrage, `quiet` est vrai (`src/extension.ts:134`) : aucun avertissement visible. Aucune branche du code ne détecte spécifiquement l'absence de réseau.
- **Non établissable par lecture** :
  - le contenu et le code de sortie réels de pip hors ligne ;
  - la durée avant échec, car aucune limite de temps n'est posée (`src/shared/utils.ts:169-171`) et les délais de pip ne sont pas dans les sources lues ;
  - le fait que `python3 -m venv` réussisse hors ligne, et que pip soit disponible dans le venv créé ;
  - l'état partiel du venv ou des paquets après un échec ;
  - le comportement du démarrage suivant après un échec : le venv existe alors (`src/shared/utils.ts:122`) mais le contenu dépend de ce qui précède.

## 6. Synthèse déduite du flux de démarrage

1. `activate` → si un dossier de workspace est ouvert, résolution de l'exécutable (`src/extension.ts:130-133`).
2. Sans venv existant, l'exécutable est `python3` (`src/shared/utils.ts:195`) : création de `backends/.venv` (`src/shared/utils.ts:120-140`).
3. Test d'import de `unicorn` et `capstone` (`src/shared/utils.ts:150-161`).
4. En cas d'échec d'un import : `pip install -r requirements.txt --quiet --break-system-packages` (`src/shared/utils.ts:169`).
5. Aucune demande à l'utilisateur à aucune étape ; aucun message visible au démarrage (`src/extension.ts:134`).
