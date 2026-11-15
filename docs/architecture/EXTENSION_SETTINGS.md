# Inventaire des réglages de l'extension

## Périmètre et méthode

- Inventaire factuel établi par lecture statique de `extension/package.json` et de `extension/src/`, au commit de base `0e96a4f75f8622009cce572262b105e1962b43e4`.
- Aucune exécution de code, aucun test dynamique : aucune affirmation sur le comportement observé à l'exécution.
- Les références `chemin:ligne` renvoient à ce commit. Les chemins sont relatifs à la racine du dépôt.
- Aucune correction ni recommandation n'est formulée.
- Les fichiers de `extension/src/tests/` ne sont pas comptés comme points de lecture. Ils ne contiennent que des doubles de `getConfiguration`.
- Les descriptions déclarées sont des clés de localisation `%...%`. Leur texte n'est pas dans les sources autorisées et n'est donc pas reproduit.

### Distinction utilisée

- **Contrainte déclarative** : propriété de `contributes.configuration` (`type`, `enum`, `minimum`, `maximum`, `default`). Elle est portée par `package.json`. Ce document ne dit pas comment l'hôte l'applique.
- **Contrôle à la lecture** : instruction exécutable dans `extension/src/` qui coerce, compare ou rejette la valeur lue. Une annotation de type TypeScript n'est pas comptée comme contrôle.
- **Coercition** : conversion (`Number(...)`, `Boolean(...)`, `String(...)`) qui ne rejette rien en elle-même. Elle est signalée comme telle.
- `Valeur par défaut du code` désigne le second argument de `get(clé, défaut)`.

## 1. Réglages déclarés dans `contributes.configuration`

Section `contributes.configuration` : `extension/package.json:298-392`, titre `Pile ou Face` (`extension/package.json:299`). 12 réglages sont déclarés. « — » signifie que le champ est absent de la déclaration.

| Clé | Type | Défaut | Bornes / énumération | Description (clé) | Autres champs | Lignes |
|---|---|---|---|---|---|---|
| `pileOuFace.authServerUrl` | `string` | `""` | — | `%config.authServerUrl%` | — | `extension/package.json:301-305` |
| `pileOuFace.logLevel` | `string` | `"warning"` | enum : `debug`, `info`, `warning`, `error` | `%config.logLevel%` | — | `extension/package.json:306-316` |
| `pileOuFace.keymap` | `string` | `"default"` | enum : `default`, `ida` | `%config.keymap%` | `enumDescriptions` : `%config.keymap.default%`, `%config.keymap.ida%` | `extension/package.json:317-329` |
| `pileOuFace.perfDiagnostics` | `boolean` | `false` | — | `%config.perfDiagnostics%` | — | `extension/package.json:330-334` |
| `pileOuFace.autoTriage.enabled` | `boolean` | `false` | — | `%config.autoTriage.enabled%` | `tags` : `usesOnlineServices` | `extension/package.json:335-342` |
| `pileOuFace.autoTriage.model` | `string` | `""` | — | `%config.autoTriage.model%` | — | `extension/package.json:343-347` |
| `pileOuFace.autoTriage.maxFunctions` | `integer` | `200` | minimum `1`, maximum `1000` | `%config.autoTriage.maxFunctions%` | — | `extension/package.json:348-354` |
| `pileOuFace.autoTriage.maxSeconds` | `integer` | `600` | minimum `30`, maximum `7200` | `%config.autoTriage.maxSeconds%` | — | `extension/package.json:355-361` |
| `pileOuFace.autoTriage.maxTokensPerRequest` | `integer` | `2048` | minimum `128`, maximum `32768` | `%config.autoTriage.maxTokensPerRequest%` | — | `extension/package.json:362-368` |
| `pileOuFace.autoTriage.maxTotalTokens` | `integer` | `100000` | minimum `1024`, maximum `1000000` | `%config.autoTriage.maxTotalTokens%` | — | `extension/package.json:369-375` |
| `pileOuFace.telemetry.enabled` | `boolean` | `true` | — | `%config.telemetry.enabled%` | `scope` : `machine` ; `tags` : `telemetry`, `usesOnlineServices` | `extension/package.json:376-385` |
| `pileOuFace.runtimeUsageAudit` | `boolean` | `false` | — | `%config.runtimeUsageAudit%` | — | `extension/package.json:386-390` |

Autres usages déclaratifs de ces clés dans `package.json` :

- `config.pileOuFace.perfDiagnostics == true` est la condition `when` de la commande `pileOuFace.perfSnapshot` dans `commandPalette` (`extension/package.json:247-250`).

## 2. Points de lecture et vérifications, par réglage déclaré

### `pileOuFace.authServerUrl`

Lu par `getConfiguration('pileOuFace').inspect('authServerUrl')`. Seules les valeurs `workspaceFolderValue`, `workspaceValue` et `globalValue` sont prises, dans cet ordre, avec `''` en repli.

| Point de lecture | Vérification appliquée à la lecture |
|---|---|
| `extension/src/extension.ts:141-143` | Aucune à la lecture. La valeur est passée à `planLegacyAuthUrlMigration` (`extension/src/extension.ts:144-148`) et à `resolveAuthServerUrl` (`extension/src/extension.ts:149-154`). |
| `extension/src/static/staticHandlers.ts:475-482` | Aucune à la lecture. La valeur est passée à `resolveAuthServerUrl`. |
| `extension/src/static/hub.ts:294-304` | Aucune à la lecture. La valeur est passée à `resolveAuthServerUrl`, dans un `try` dont le `catch` appelle `resolveAuthServerUrl({ projectRoot: root })` (`extension/src/static/hub.ts:302-303`). |

Contrôles exécutés dans `resolveAuthServerUrl` (`extension/src/shared/authConfig.ts:103-136`) :

- La valeur configurée est passée à `requireSecureAuthUrl` (`extension/src/shared/authConfig.ts:118`).
- `requireSecureAuthUrl` (`extension/src/shared/authConfig.ts:62-70`) :
  - retourne `''` si la valeur normalisée est vide (`extension/src/shared/authConfig.ts:64`) ;
  - construit `new URL(url)` (`extension/src/shared/authConfig.ts:65`) ;
  - lève `Auth server URL must use HTTPS outside loopback` si le protocole n'est pas `https:` et que l'hôte n'est pas `localhost`, `127.0.0.1` ou `::1` (`extension/src/shared/authConfig.ts:66-68`) ;
  - retire un `/` final (`extension/src/shared/authConfig.ts:69`).
- Dans `planLegacyAuthUrlMigration` (`extension/src/shared/authConfig.ts:72-83`), `requireSecureAuthUrl` n'est appliqué qu'à l'URL héritée (`legacyUrl`), et seulement pour le profil `OSS_DEVELOPMENT` quand aucune URL configurée n'existe (`extension/src/shared/authConfig.ts:79-80`). La valeur configurée n'y est que normalisée (`extension/src/shared/authConfig.ts:78`, `82`).

Autre point d'accès : le réglage est écrit via `getConfiguration('pileOuFace').update('authServerUrl', ...)` (`extension/src/extension.ts:158-159`). Ce n'est pas une lecture.

### `pileOuFace.logLevel`

| Point de lecture | Vérification appliquée à la lecture |
|---|---|
| `extension/src/extension.ts:119` (`get('logLevel', 'warning')`) | Aucune au point de lecture. La valeur est passée à `logger.setLevel` (`extension/src/extension.ts:120`). |
| Réaction au changement : `extension/src/extension.ts:124-126` (`affectsConfiguration('pileOuFace.logLevel')`) | Pas de lecture directe : relance `applyLogLevelFromConfig`. |

Contrôle exécuté en aval : `setLevel` appelle `normalizeLevel` (`extension/src/shared/logger.ts:19-21`). Celui-ci applique `String(...).trim().toLowerCase()` puis vérifie l'appartenance à `LEVELS` (`debug`, `info`, `warning`, `error`) et retombe sur `warning` sinon (`extension/src/shared/logger.ts:9-17`).

### `pileOuFace.keymap`

| Point de lecture | Vérification appliquée à la lecture |
|---|---|
| `extension/src/static/hub.ts:213` (`get('keymap', 'default') === 'ida'`) | Comparaison stricte à `'ida'`. Toute autre valeur donne `false`. Il n'y a ni contrôle de type, ni rejet d'une valeur hors énumération. |
| `extension/src/static/hub.ts:224-227` (`affectsConfiguration('pileOuFace.keymap')`) | Pas de lecture directe : appelle `postKeymapConfig` (`extension/src/static/hub.ts:218-222`), qui relit via `idaKeymapEnabled`. |

L'énumération `default` / `ida` n'est portée que par la déclaration (`extension/package.json:318-326`).

### `pileOuFace.perfDiagnostics`

| Point de lecture | Vérification appliquée à la lecture |
|---|---|
| `extension/src/static/hub.ts:206` (`get('perfDiagnostics', false)`) | Coercition `Boolean(...)`, dans un `try` qui retourne `false` en cas d'exception (`extension/src/static/hub.ts:204-210`). |
| `extension/src/static/hub/actions.ts:73` (`get('perfDiagnostics', false)`) | Coercition `Boolean(...)`, dans un `try` qui retourne `false` en cas d'exception (`extension/src/static/hub/actions.ts:71-77`). |

Consommateurs de ces lectures : `extension/src/static/hub.ts:231`, `425`, `565`, `966` et `extension/src/static/hub/actions.ts:516`. Il n'y a aucun contrôle de type autre que la coercition.

### `pileOuFace.autoTriage.enabled`

| Point de lecture | Vérification appliquée à la lecture |
|---|---|
| `extension/src/static/hub/actions.ts:93` (`get('autoTriage.enabled', false)`) | Coercition `Boolean(...)`, dans un `try` qui retourne `false` en cas d'exception (`extension/src/static/hub/actions.ts:91-97`). |

Consommateur : `extension/src/static/hub/actions.ts:156`. Aucun autre point de lecture n'a été repéré.

### `pileOuFace.autoTriage.model`

| Point de lecture | Vérification appliquée à la lecture |
|---|---|
| `extension/src/static/staticHandlers.ts:511-513` (`get('autoTriage.model', '')`) | Coercition `String(... \|\| '').trim()`. Aucune vérification de format à cet endroit. |

Exploitation de la valeur lue : si elle est non vide, elle est découpée sur le premier `@` (`extension/src/static/staticHandlers.ts:514-517`). Un `@` en position 0 ou absent donne le fournisseur `ollama` (`extension/src/static/staticHandlers.ts:516`). Aucune liste de valeurs autorisées n'a été repérée dans ce bloc.

### `pileOuFace.autoTriage.maxFunctions`

| Point de lecture | Vérification appliquée à la lecture |
|---|---|
| `extension/src/static/staticHandlers.ts:1621-1622` (`get('maxFunctions', 200)`) | Coercition `Number(...)`. Aucun contrôle de borne, d'entier ou de minimum/maximum sur la valeur de configuration. |
| `extension/src/static/staticHandlers.ts:1836`, `1843` (`get('maxFunctions', 200)`) | Coercition `Number(...)`. Aucun contrôle de borne. Valeur transmise au webview (`extension/src/static/staticHandlers.ts:1837-1847`). |

Au point `1626-1628`, la valeur de configuration n'est utilisée que si `message.maxFunctions` n'est pas un entier strictement positif. Ce contrôle (`Number.isInteger(...) && > 0`) porte sur la valeur du message, pas sur la valeur de configuration.

### `pileOuFace.autoTriage.maxSeconds`

| Point de lecture | Vérification appliquée à la lecture |
|---|---|
| `extension/src/static/staticHandlers.ts:1621`, `1623` (`get('maxSeconds', 600)`) | Coercition `Number(...)`. Aucun contrôle de borne sur la valeur de configuration. |
| `extension/src/static/staticHandlers.ts:1836`, `1844` (`get('maxSeconds', 600)`) | Coercition `Number(...)`. Aucun contrôle de borne. |

Au point `1629-1631`, le contrôle `Number.isFinite(...) && > 0` porte sur `message.maxSeconds`, pas sur la valeur de configuration.

### `pileOuFace.autoTriage.maxTokensPerRequest`

| Point de lecture | Vérification appliquée à la lecture |
|---|---|
| `extension/src/static/staticHandlers.ts:1621`, `1624` (`get('maxTokensPerRequest', 2048)`) | Coercition `Number(...)`. Aucun contrôle de borne sur la valeur de configuration. |
| `extension/src/static/staticHandlers.ts:1836`, `1845` (`get('maxTokensPerRequest', 2048)`) | Coercition `Number(...)`. Aucun contrôle de borne. |

Au point `1632-1634`, le contrôle `Number.isInteger(...) && > 0` porte sur `message.maxTokens`, pas sur la valeur de configuration.

### `pileOuFace.autoTriage.maxTotalTokens`

| Point de lecture | Vérification appliquée à la lecture |
|---|---|
| `extension/src/static/staticHandlers.ts:1621`, `1625` (`get('maxTotalTokens', 100000)`) | Coercition `Number(...)`. Aucun contrôle de borne sur la valeur de configuration. |
| `extension/src/static/staticHandlers.ts:1836`, `1846` (`get('maxTotalTokens', 100000)`) | Coercition `Number(...)`. Aucun contrôle de borne. |

Au point `1635-1637`, le contrôle `Number.isInteger(...) && > 0` porte sur `message.maxTotalTokens`, pas sur la valeur de configuration.

### `pileOuFace.telemetry.enabled`

| Point de lecture | Vérification appliquée à la lecture |
|---|---|
| `extension/src/shared/telemetry/telemetry.ts:75` (`get('telemetry.enabled', true) === true`) | Comparaison stricte à `true`. Une valeur non booléenne donne `false`. Dans un `try` dont le `catch` retourne `false` (`extension/src/shared/telemetry/telemetry.ts:73-79`). |
| `extension/src/shared/telemetry/telemetry.ts:127-130` (`affectsConfiguration('pileOuFace.telemetry.enabled')`) | Pas de lecture directe : appelle `handleEnablementChange`. |

`isProductTelemetryEnabled` est utilisé dans `isEnabled` (`extension/src/shared/telemetry/telemetry.ts:81-88`) avec d'autres conditions (`vscode.env.isTelemetryEnabled === true`, etc.). Cet état global de VS Code n'est pas un réglage `pileOuFace.*`.

### `pileOuFace.runtimeUsageAudit`

| Point de lecture | Vérification appliquée à la lecture |
|---|---|
| `extension/src/extension.ts:115` (`get('runtimeUsageAudit', false)`) | Aucune au point de lecture. |
| `extension/src/extension.ts:116` | Comparaison stricte `auditEnabled === true` à l'appel de `configureRuntimeAudit`. Toute valeur non booléenne `true` donne `false`. |

Aucune réaction à un changement de ce réglage (pas d'`affectsConfiguration` repéré pour cette clé). La lecture est faite une fois dans `extension/src/extension.ts:115`.

## 3. Récapitulatif des vérifications

| Clé | Contraintes déclaratives (`package.json`) | Contrôle à la lecture dans `extension/src/` |
|---|---|---|
| `pileOuFace.authServerUrl` | type `string` | Oui, en aval : URL valide et HTTPS hors boucle locale (`extension/src/shared/authConfig.ts:62-70`) |
| `pileOuFace.logLevel` | type `string`, enum de 4 valeurs | Oui, en aval : normalisation vers `warning` (`extension/src/shared/logger.ts:14-17`) |
| `pileOuFace.keymap` | type `string`, enum de 2 valeurs | Comparaison à `'ida'` seulement (`extension/src/static/hub.ts:213`) |
| `pileOuFace.perfDiagnostics` | type `boolean` | Coercition `Boolean` |
| `pileOuFace.autoTriage.enabled` | type `boolean` | Coercition `Boolean` |
| `pileOuFace.autoTriage.model` | type `string` | Coercition `String` + `trim` |
| `pileOuFace.autoTriage.maxFunctions` | type `integer`, 1 à 1000 | Coercition `Number`, aucune borne |
| `pileOuFace.autoTriage.maxSeconds` | type `integer`, 30 à 7200 | Coercition `Number`, aucune borne |
| `pileOuFace.autoTriage.maxTokensPerRequest` | type `integer`, 128 à 32768 | Coercition `Number`, aucune borne |
| `pileOuFace.autoTriage.maxTotalTokens` | type `integer`, 1024 à 1000000 | Coercition `Number`, aucune borne |
| `pileOuFace.telemetry.enabled` | type `boolean` | Comparaison stricte `=== true` |
| `pileOuFace.runtimeUsageAudit` | type `boolean` | Comparaison stricte `=== true` |

Lectures absentes : aucun réglage déclaré n'est dépourvu de point de lecture dans `extension/src/` (hors tests). Chacun des 12 réglages a au moins un point de lecture repéré dans la section 2.

## 4. Réglages lus dans `extension/src/` sans déclaration dans `contributes.configuration`

Tous les appels à `getConfiguration` repérés hors tests visent la section `pileOuFace` ou `pileOuFace.autoTriage` (`extension/src/extension.ts:115`, `119`, `141`, `158` ; `extension/src/static/hub.ts:206`, `213`, `296` ; `extension/src/static/hub/actions.ts:73`, `93` ; `extension/src/static/staticHandlers.ts:476`, `512`, `1621`, `1836` ; `extension/src/shared/telemetry/telemetry.ts:75`). Toutes les clés lues dans ces appels sont déclarées dans la section 1. Aucune clé `getConfiguration` non déclarée n'a été repérée hors tests.

### `pythonPath` : lu hors configuration VS Code

`pythonPath` n'est pas déclaré dans `contributes.configuration` et n'est pas lu par `getConfiguration`. Il provient de l'objet enregistré sous la clé `pof-settings` du `globalState` de l'extension.

| Point de lecture | Détail |
|---|---|
| `extension/src/extension.ts:201-202` | `savedSettings.pythonPath \|\| (root ? detectPythonExecutable(root) : 'python3')` |
| `extension/src/static/staticHandlers.ts:467-474` | `getSavedSettings().pythonPath \|\| detectPythonExecutable(root)` |
| `extension/src/shared/sharedHandlers.ts:758-761` | Idem, dans `hubAiProvidersGet` |
| `extension/src/shared/sharedHandlers.ts:777-780` | Idem |
| `extension/src/shared/sharedHandlers.ts:814-817` | Idem |
| `extension/src/shared/sharedHandlers.ts:843-846` | Idem |
| `extension/src/shared/sharedHandlers.ts:877-880` | Idem |

Vérifications observées sur cette valeur :

- Seule la valeur est testée comme « vraie » (opérateur `||`). Aucun contrôle de type, d'existence du fichier ni de chemin n'est repéré à ces points de lecture.
- `getSavedSettings` retourne `{}` si la lecture du `globalState` lève une exception (`extension/src/static/staticHandlers.ts:467-473`, `extension/src/shared/sharedHandlers.ts:759`). Le `|| {}` couvre aussi une valeur fausse.
- `detectPythonExecutable(root, settingsPythonPath)` (`extension/src/shared/utils.ts:184-185`) accepte un chemin en second paramètre et le retourne s'il est « vrai ». Les appels repérés à `detectPythonExecutable(root)` dans les lectures ci-dessus ne passent pas ce paramètre. D'autres appelants n'ont pas été inventoriés ici.

Valeur par défaut et écriture :

- `SETTINGS_DEFAULTS.pythonPath` vaut `''` (`extension/src/static/hub.ts:152-153`).
- `hubGetSettings` fusionne `SETTINGS_DEFAULTS` et la valeur stockée (`extension/src/static/hub/actions.ts:1183-1186`).
- `hubSaveSettings` enregistre `message.settings` tel quel dans `pof-settings` (`extension/src/static/hub/actions.ts:1188-1191`). Aucun contrôle de type ni de contenu n'y est repéré.
- `hubResetSettings` remet `SETTINGS_DEFAULTS` (`extension/src/static/hub/actions.ts:1193-1196`).

Aucun réglage équivalent à `pythonPath` n'a été repéré dans `getConfiguration`.

### Autres clés de `pof-settings`

L'objet `pof-settings` contient d'autres clés déclarées dans `SETTINGS_DEFAULTS` (`extension/src/static/hub.ts:152-169`) : `pythonPath`, `authServerUrl`, `aiTemperature`, `aiTopP`, `aiMaxTokens`, `aiPricingRules`, `decompilerProvider`, `decompilerLocalPaths`, `stringsEncoding`, `stringsMinLen`, `asmSyntax`, `lang`, `defaultPanel`, `codeFontSize`, `interfaceMode`, `enabledStaticFeatures`. Elles ne figurent pas dans `contributes.configuration`. Seules les lectures suivantes ont été relevées dans le cadre de cet inventaire :

| Clé | Point de lecture | Vérification à la lecture |
|---|---|---|
| `authServerUrl` | `extension/src/extension.ts:142`, `146`, `150` ; `extension/src/static/staticHandlers.ts:478` ; `extension/src/static/hub.ts:298` | Valeur utilisée comme `savedAuthServerUrl` ; contrôle en aval par `requireSecureAuthUrl` (`extension/src/shared/authConfig.ts:117`) |
| `decompilerLocalPaths` | `extension/src/static/staticHandlers.ts:495-498`, `504` | Contrôle de type objet (`typeof ... === 'object'`), puis `String(localPaths.ghidra \|\| '').trim()` |

Les lectures des autres clés (`aiTemperature`, `aiTopP`, etc.) n'ont pas été inventoriées : elles sortent du périmètre demandé, centré sur les réglages et sur `pythonPath`.

## 5. Limites de cet inventaire

- Lecture statique uniquement : aucune affirmation sur ce qui se passe à l'exécution (valeurs effectivement reçues, application des bornes par l'hôte VS Code, etc.).
- Le texte des descriptions (`%config.*%`) n'est pas dans les sources autorisées.
- La recherche des points de lecture s'appuie sur les motifs `getConfiguration`, `inspect`, `affectsConfiguration`, `pof-settings` et `pythonPath` dans `extension/src/`. Un accès indirect qui n'utiliserait aucun de ces motifs ne serait pas visible ici.
