# Inventaire des postMessage asynchrones vers les webviews du hub

## Périmètre et méthode

- Source unique : `extension/src/shared/sharedHandlers.ts`, au commit de base `0e96a4f75f8622009cce572262b105e1962b43e4`. Les numéros de ligne se rapportent à ce commit.
- Méthode : lecture statique uniquement. Aucune exécution du code, des tests applicatifs ou des scénarios E2E. Aucune observation d'exécution n'est affirmée, et aucun comportement d'un autre fichier n'est déduit.
- Le document décrit des faits. Il ne juge pas les protections observées et ne propose aucune correction.

### Appels recensés

Un appel est recensé quand il se trouve dans l'un des contextes suivants :

1. un rappel de `cp.execFile` ;
2. une suite de `.then` (aucune occurrence de `.then(` dans le fichier) ;
3. une fonction `async` après un `await` situé plus haut dans le même corps de fonction (ou dans la fonction qui appelle l'assistant concerné) ;
4. un bloc `catch` associé à un `try` contenant un `await`, ou un rappel `execFile`.

Les appels `safePostMessage(...)` sont comptés par site d'appel. L'unique `postMessage` interne de cet assistant est à la ligne 290.

### Vérification d'ouverture du panneau ou de la webview

Aucune ligne du fichier ne teste l'état du panneau ou de la webview avant un envoi (aucune lecture de `visible`, `disposed` ou équivalent, constat par recherche textuelle dans `sharedHandlers.ts`). Cette colonne vaut donc « absente » pour tous les appels. Le seul mécanisme voisin est le `try`/`catch` de `safePostMessage` (lignes 288-294), dont le commentaire ligne 292 mentionne un hub potentiellement disposé.

### Règle de classement

- **Protégé** : l'appel est lexiquement dans un bloc `try` qui possède une clause `catch` dans la même fonction, ou l'appel passe par `safePostMessage` (`try`/`catch` lignes 289-293). Une exception levée par l'envoi est alors rattrapée.
- **Non protégé** : tous les autres appels. Le `try` éventuel d'une fonction appelante n'est pas pris en compte pour le classement et il est signalé dans les notes.
- **Dans un catch** : l'appel est lexiquement dans un bloc `catch`. Ce critère est indépendant du précédent et se recoupe avec lui : un appel dans un `catch` est protégé seulement s'il passe par `safePostMessage` ou s'il est dans un autre `try` imbriqué.
- Un `catch` qui rattrape l'exception d'envoi n'apporte pas de protection au `postMessage` qu'il contient lui-même.

## Inventaire

Toutes les références sont de la forme `extension/src/shared/sharedHandlers.ts:ligne`. Pour abréger, le préfixe est omis dans les tableaux : « L313 » signifie `extension/src/shared/sharedHandlers.ts:313`.

### Assistants et fonctions internes

| # | Appel | Gestionnaire | Opération asynchrone précédente | Vérif. panneau | Rattrapage de l'envoi | Classement |
|---|-------|--------------|---------------------------------|----------------|-----------------------|------------|
| 1 | L313 | `forgetRecentBinary` (appelé L332 depuis `handleMissingBinarySelection`) | `await vscode.window.showWarningMessage` (L324) | absente | aucun `try` dans L312-314 ni autour de L332 (L321-348) | non protégé |
| 2 | L307 | `notifyAnnotations` | `await annotationsBridge.*` chez les appelants (L671, L683, L697, L708, L718, L729, L740, L751) | absente | aucun `try` dans L306-309 ; les appelants l'invoquent dans un `try` dont le `catch` appelle `showErrorMessage` (par ex. L670-676) | non protégé |
| 3 | L308 | `notifyAnnotations` | idem n° 2 | absente | idem n° 2 | non protégé |
| 4 | L344 | `handleMissingBinarySelection` | `await patchHistoryBridge.deleteHistory` (L336), après `await` L324, L333, L334 | absente | aucun `try` dans L321-348 | non protégé |
| 5 | L345 | `handleMissingBinarySelection` | idem n° 4 | absente | aucun `try` dans L321-348 | non protégé |

### Gestionnaires après `await`

| # | Appel | Gestionnaire | Opération asynchrone précédente | Vérif. panneau | Rattrapage de l'envoi | Classement |
|---|-------|--------------|---------------------------------|----------------|-----------------------|------------|
| 6 | L521 | `requestBinarySelection` | `await rememberBinarySelection` (L520) | absente | aucun `try` dans L509-527 | non protégé |
| 7 | L537 | `hubUseBinaryPath` | `await rememberBinarySelection` (L536) | absente | aucun `try` dans L528-543 | non protégé |
| 8 | L556 | `hubForgetRecentBinary` | `await patchHistoryBridge.deleteHistory` (L554) | absente | aucun `try` dans L544-559 | non protégé |
| 9 | L557 | `hubForgetRecentBinary` | idem n° 8 | absente | aucun `try` dans L544-559 | non protégé |
| 10 | L571 | `hubRequestRecentBinaries` | `await setRecentBinariesState` (L569), exécuté seulement si la condition L567 est vraie | absente | aucun `try` dans L564-572 | non protégé |
| 11 | L589 | `requestRulesSelection` | `await vscode.window.showOpenDialog` (L575) | absente | aucun `try` dans L573-591 | non protégé |
| 12 | L611 | `cleanupGeneratedFiles` | `await vscode.window.showWarningMessage` (L598), exécuté seulement si `message?.confirm` (L597) | absente | aucun `try` dans L596-613 | non protégé |
| 13 | L612 | `cleanupGeneratedFiles` | idem n° 12 | absente | aucun `try` dans L596-613 | non protégé |
| 14 | L623 | `purgeStaleCache` | `await patchHistoryBridge.purgeMissing` (L616) | absente | aucun `try` dans L614-625 | non protégé |
| 15 | L624 | `purgeStaleCache` | idem n° 14 | absente | aucun `try` dans L614-625 | non protégé |
| 16 | L632 | `hubLoadChatHistory` | `await chatHistoryBridge.loadHistory` (L631) | absente | dans le `try` L630-633, `catch` L633 | protégé |
| 17 | L661 | `hubLoadAnnotations` | `await annotationsBridge.loadAnnotations` (L660) | absente | dans le `try` L659-662, `catch` L662 (appelle `showErrorMessage`, L663) | protégé |

### Appels dans un bloc `catch` d'un gestionnaire `async`

| # | Appel | Gestionnaire | Opération asynchrone précédente | Vérif. panneau | Rattrapage de l'envoi | Classement |
|---|-------|--------------|---------------------------------|----------------|-----------------------|------------|
| 18 | L634 | `hubLoadChatHistory` | `catch` L633 du `await` L631 | absente | aucun `try` autour de L634 | non protégé, dans un catch |
| 19 | L647 | `hubSaveChatHistory` | `catch` L646 du `await chatHistoryBridge.saveHistory` (L642) | absente | aucun `try` autour de L647 | non protégé, dans un catch |

### Rappels de `cp.execFile`

| # | Appel | Gestionnaire | Opération asynchrone précédente | Vérif. panneau | Rattrapage de l'envoi | Classement |
|---|-------|--------------|---------------------------------|----------------|-----------------------|------------|
| 20 | L765 (`safePostMessage`, envoi réel L290) | `hubAiProvidersGet` | rappel de `cp.execFile` (L763), branche `err` | absente | `try`/`catch` de `safePostMessage` (L289-293), `catch` vide avec commentaire L292 | protégé |
| 21 | L770 (`safePostMessage`) | `hubAiProvidersGet` | rappel de `cp.execFile` (L763), dans le `try` L768 | absente | `safePostMessage` (L289-293) | protégé |
| 22 | L772 (`safePostMessage`) | `hubAiProvidersGet` | `catch` L771 du `JSON.parse` (L769) dans le rappel de `cp.execFile` (L763) | absente | `safePostMessage` (L289-293) | protégé, dans un catch |
| 23 | L786 | `hubAiProviderSet` | rappel de `cp.execFile` (L784), branche `err` | absente | aucun `try` autour de L786 | non protégé |
| 24 | L792 | `hubAiProviderSet` | rappel de `cp.execFile` (L784), dans le `try` L789, après `JSON.parse` (L790) | absente | `try` L789, `catch` L795 (vide, commentaire L796) | protégé |
| 25 | L803 | `hubAiProviderSet` | rappel du second `cp.execFile` (L800), dans le `try` L801 | absente | `try` L801, `catch` L804 | protégé |
| 26 | L805 | `hubAiProviderSet` | `catch` L804 du `JSON.parse` (L802), second `cp.execFile` (L800) | absente | aucun `try` autour de L805 | non protégé, dans un catch |
| 27 | L822 | `hubAiProviderTest` | rappel de `cp.execFile` (L820), branche `err` | absente | aucun `try` autour de L822 | non protégé |
| 28 | L827 | `hubAiProviderTest` | rappel de `cp.execFile` (L820), dans le `try` L825 | absente | `try` L825, `catch` L837 | protégé |
| 29 | L838 | `hubAiProviderTest` | `catch` L837 du `try` L825, rappel de `cp.execFile` (L820) | absente | aucun `try` autour de L838 | non protégé, dans un catch |
| 30 | L854 | `hubAiProviderDefaultSet` | rappel de `cp.execFile` (L848), branche `err` | absente | aucun `try` autour de L854 | non protégé |
| 31 | L862 | `hubAiProviderDefaultSet` | rappel de `cp.execFile` (L848), dans le `try` L860 | absente | `try` L860, `catch` L866 | protégé |
| 32 | L867 | `hubAiProviderDefaultSet` | `catch` L866 du `try` L860, rappel de `cp.execFile` (L848) | absente | aucun `try` autour de L867 | non protégé, dans un catch |

## Décompte

Base : 32 sites d'appel recensés (29 `postMessage` directs et 3 invocations de `safePostMessage`).

| Catégorie | Nombre | Numéros |
|-----------|--------|---------|
| Protégés | 9 | 16, 17, 20, 21, 22, 24, 25, 28, 31 |
| Non protégés | 23 | 1 à 15, 18, 19, 23, 26, 27, 29, 30, 32 |
| Situés dans un bloc `catch` | 6 | 18, 19, 22, 26, 29, 32 |

Recoupement : protégés + non protégés = 32. La catégorie « dans un `catch` » recoupe les deux autres : 5 appels dans un `catch` sont non protégés (18, 19, 26, 29, 32) et 1 est protégé (22, via `safePostMessage`).

## Appels asynchrones complémentaires hors règle de recensement

Ces appels sont dans des rappels de `cp.spawn`, de `readline` ou de temporisateurs (`setTimeout`), dans `hubAiProviderPrompt` (L875-992). Ils ne relèvent ni de `cp.execFile`, ni de `.then`, ni d'un `await` précédent, et ils sont exclus du décompte. Pour chacun : vérification de l'état du panneau absente, aucun `try`/`catch` autour de l'appel.

| Appel | Fonction | Contexte asynchrone | Observation |
|-------|----------|---------------------|-------------|
| L917 | `flushTokenBuffer` (L907) | appelée depuis un temporisateur (L926), `sendResult` (L933) et `cancelRequest` (L950) | non protégé |
| L935 | `sendResult` (L929) | rappel de `setTimeout` (L934) | non protégé |
| L953 | `cancelRequest` (L947) | fonction enregistrée via `registerAiProcess` (L962) | non protégé |

## Appels non asynchrones exclus

- L507 (`getPlatform`), L594 (`listGeneratedFiles`), L656 (`hubLoadAnnotations`, branche `!binaryPath` avant tout `await`) et L996 (`hubAiCancel`) s'exécutent sans opération asynchrone préalable dans leur chemin.
- Les appels `showErrorMessage` ou `showInformationMessage` ne sont pas des `postMessage`.

## Limites

- Constats issus de la seule lecture de `sharedHandlers.ts`. Le comportement de `panel.webview.postMessage` (lever ou non une exception, valeur renvoyée) n'est pas décrit : il dépend de code hors du fichier.
- Le fichier ne contient aucune vérification d'état du panneau ; les gestionnaires peuvent être appelés par du code hors du fichier, non étudié ici.
