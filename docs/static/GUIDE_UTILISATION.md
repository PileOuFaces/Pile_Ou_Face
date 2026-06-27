# Guide pratique des fonctionnalites statiques

Ce document explique comment utiliser les principales fonctionnalites statiques de Pile ou Face, puis comment interpreter leurs resultats sans sur-promettre.

Il complete :

- [FONCTIONNALITES.md](FONCTIONNALITES.md) pour la vue catalogue ;
- [ARCHITECTURE.md](ARCHITECTURE.md) pour comprendre les couches ;
- [README.md](README.md) pour la documentation technique complete des modules.

## Avant de commencer

Workflow conseille :

1. Charger un binaire.
2. Regarder `Infos`, `Sections`, `Symboles` et `Strings`.
3. Aller vers `Fonctions`, commencer par le `Radar`, puis ouvrir `Desassemblage`, `CFG` et `Call Graph`.
4. Utiliser ensuite `Decompilateur`, `Stack Frame`, `Recherche`, `Hex View`.
5. Si des plugins sont installes, finir par les vues heuristiques : `Behavior`, `Taint`, `Anti-analyse`, `YARA`, `CAPA`, `Vulnerabilites`, `ROP`, `FLIRT`, `Deobfuscation`.

Regle d'interpretation simple :

- Les vues `DATA` de base sont en general les plus fiables.
- Les vues `CODE` aident beaucoup, mais certaines reposent sur des heuristiques.
- Les vues `AUDIT`, `MALWARE` et `OFFENSIF` sont pluginisees.
- Quand elles apparaissent, elles restent surtout des signaux d'audit, pas des preuves a elles seules.

## Niveau de confiance a garder en tete

Tu peux presenter les resultats comme suit :

- `Fort niveau de confiance` : infos binaire, sections, strings, symboles, imports/exports, recherche, hex view.
- `Bon niveau de confiance avec limites` : desassemblage, fonctions, xrefs, call graph simple, stack frame avec debug info.
- `Heuristique utile` : CFG complexe, calling convention, decompilation, behavior, anti-analyse, taint, deobfuscation, FLIRT, ROP.
- `Signal d'audit` : vuln_patterns, YARA, CAPA, similarity, bindiff.

## CODE

### Desassemblage

A quoi ca sert :

- Lire les instructions machine sous forme assembleur.
- Naviguer par adresse, symbole ou section.
- Verifier ce qu'une fonction fait vraiment.

Comment l'utiliser :

- Ouvrir l'onglet de desassemblage depuis le hub.
- Chercher `main`, `_start`, une adresse ou un symbole.
- Utiliser les xrefs et les labels pour remonter les appels.
- Revenir souvent au desassemblage quand une autre vue parait ambiguë.

Comment interpreter :

- Les `call` montrent les appels directs.
- Les `cmp`, `test`, `jz`, `jnz`, `jmp` montrent les conditions et bifurcations.
- Les acces a `[rbp-...]` ou `[sp+...]` montrent souvent des variables locales.
- Une comparaison avec une constante ou une string aide a comprendre une condition metier.

Pieges frequents :

- Un appel indirect (`call rax`, pointeur de fonction, vtable) est plus dur a reconstruire.
- Un binaire tres optimise peut etre plus compact et moins lisible.
- Sur un binaire stripe, les noms de fonctions peuvent manquer.

### CFG

A quoi ca sert :

- Visualiser le flux de controle d'une fonction.
- Comprendre rapidement les branches, les boucles et les sorties.

Comment l'utiliser :

- Partir d'une fonction importante comme `main`, `handle_action`, `check_password`.
- Basculer entre mode tableau et mode graphique.
- Cliquer sur les blocs pour naviguer vers le desassemblage.

Comment interpreter :

- Un losange logique correspond souvent a un `if`.
- Une boucle revient vers un bloc precedent.
- Plusieurs sorties d'un bloc montrent les cas possibles d'une condition.
- Un `switch` cree souvent un noeud avec beaucoup de branches.

Pieges frequents :

- Les switch tables, les sauts indirects et certaines obfuscations compliquent le graphe.
- Un beau graphe ne garantit pas qu'il est complet.

### Call Graph

A quoi ca sert :

- Voir qui appelle qui dans le binaire.
- Reperer les fonctions centrales et les wrappers.

Comment l'utiliser :

- Partir de `main` ou d'une fonction alertee par une autre vue.
- Remonter vers les callers pour savoir qui atteint une fonction.
- Descendre vers les callees pour comprendre ce qu'elle declenche.

Comment interpreter :

- Une fonction beaucoup appelee est souvent un helper ou une fonction utilitaire.
- Une fonction presque jamais appelee mais sensible peut cacher un comportement dormant.
- Une chaine `main -> handle -> suspicious_*` raconte souvent bien l'histoire du binaire.

Pieges frequents :

- Les appels indirects peuvent manquer.
- Les bibliotheques inlines ou optimisations peuvent reduire la lisibilite du graphe.

### Fonctions

A quoi ca sert :

- Lister les fonctions connues ou reconstruites.
- Prioriser l'analyse.
- Isoler rapidement les hotspots et les quick wins via le `Radar`.

Comment l'utiliser :

- Trier ou filtrer par nom, adresse, taille, confiance.
- Commencer par le `Radar` pour voir les entrées candidates, les fonctions chaudes et les familles de signaux dominantes.
- Utiliser les filtres `Hotspots`, `Annotées`, `À revoir`, puis affiner par état de revue ou famille de signaux.
- Lire le panneau `Pourquoi` pour comprendre le breakdown du score, les preuves exactes et les callsites lies aux imports sensibles.
- Utiliser le workflow de revue persistant pour marquer une fonction `Prioritaire`, `En cours` ou `Reviewée`, avec des notes qui restent attachées au binaire.
- Exporter un `dossier` JSON par fonction quand vous voulez partager ou archiver une analyse ciblée.
- Quand une preuve pointe vers une chaîne connue, la navigation vers `Hex` conserve maintenant la taille utile au lieu de retomber sur un seul octet.
- Ouvrir les fonctions suspectes directement dans le desassemblage, le pseudo-C, le `CFG`, le `Call Graph` ou le `Hex` sans changer de contexte.
- Comparer fonctions nommees, sous-routines anonymes et wrappers.

Comment interpreter :

- Une fonction nommee `check_*`, `parse_*`, `decrypt_*`, `win`, `hidden_*` donne deja un bon indice.
- Une grande fonction avec beaucoup de blocs merite souvent le CFG ou la decompilation.
- Une petite fonction appelee partout est souvent un helper.
- Un score `Radar` eleve ne prouve rien a lui seul : il sert a maximiser le rendement de ta lecture.
- Les badges `Reseau`, `Execution`, `Secrets`, `Crypto`, etc. servent a expliquer pourquoi une fonction remonte.

Pieges frequents :

- La decouverte automatique peut rater des fonctions ou en inventer sur du code obfusque.
- Le score de confiance n'est pas une preuve mathematique.

### Decompilateur

A quoi ca sert :

- Lire plus vite la logique haut niveau en pseudo-C.

Comment l'utiliser :

- Lancer la decompilation depuis une fonction cible.
- Comparer si besoin plusieurs backends ou modes.
- Revenir au desassemblage quand un bloc pseudo-C semble bizarre.

Comment interpreter :

- Le pseudo-C est une aide a la lecture, pas la verite exacte.
- Les appels retrouves sont souvent plus fiables que les noms de variables reconstruits.
- Les `if`, `switch`, `while`, `return` aident a retrouver l'intention fonctionnelle.

Pieges frequents :

- Les types peuvent etre faux ou incomplets.
- Les variables `var_x`, `DAT_x`, `LAB_x` montrent une reconstruction partielle.
- Un pseudo-C "propre" peut parfois etre moins fidele qu'un pseudo-C plus brut.

### Hex View et patchs

A quoi ca sert :

- Lire les octets bruts.
- Verifier un offset.
- Appliquer de petits patchs de test.

Comment l'utiliser :

- Ouvrir une zone par offset ou adresse.
- Reperer la section autour.
- Selectionner les octets puis ouvrir la zone en desassemblage.
- Faire un patch local pour confirmer une hypothese simple.

Comment interpreter :

- Le hex view sert a confirmer ce que les autres vues disent.
- Une string visible dans le binaire peut etre rapprochee d'une fonction par offset.
- Un patch sur une condition ou un saut peut servir a tester une hypothese de reverse.

Pieges frequents :

- Patcher ne prouve pas l'analyse ; ca aide a la verifier.
- Un mauvais alignement ou une mauvaise architecture peut faire lire une zone de travers.

### Stack Frame

A quoi ca sert :

- Reconstruire arguments, variables locales et taille de pile.

Comment l'utiliser :

- Ouvrir la stack frame d'une fonction non triviale.
- Croiser avec le desassemblage et le pseudo-C.
- Verifier les acces a la pile quand une fonction manipule des buffers.

Comment interpreter :

- Une variable locale de type buffer est interessante dans l'audit de securite.
- Les offsets negatifs sont souvent des locaux ; les positifs dependent de l'ABI.
- La presence de noms debug ou DWARF augmente beaucoup la confiance.

Pieges frequents :

- Sans frame pointer ni debug info, la reconstruction est plus fragile.
- Les optimisations peuvent fusionner ou elider des variables.

### Binary Diff

A quoi ca sert :

- Comparer deux binaires ou deux versions.

Comment l'utiliser :

- Charger un binaire A et un binaire B.
- Regarder les fonctions `added`, `removed`, `modified`, `similar`.
- Ouvrir les differences importantes dans le code.

Comment interpreter :

- Tres utile pour un patch diff, une nouvelle version, ou deux variantes proches.
- Une fonction `modified` merite souvent un diff de logique ou de controles.
- Une fonction `added` peut correspondre a une nouvelle capacite.

Pieges frequents :

- La similarite n'est pas une equivalence semantique.
- Un changement de compilation peut produire du bruit.

## DATA

### Strings

A quoi ca sert :

- Extraire les chaines lisibles du binaire.

Comment l'utiliser :

- Commencer tres tot par cet onglet.
- Chercher URL, chemins, mots de passe, messages d'erreur, commandes, noms de fonctions.
- Filtrer par section si besoin.

Comment interpreter :

- Une string seule est un indice, pas toujours une fonctionnalite.
- Une URL, une commande shell ou un chemin systeme peut orienter toute l'analyse.
- Une string "cachee" mais jamais referencee peut etre un leurre ou une donnee morte.

Pieges frequents :

- Certaines strings viennent du runtime ou de bibliotheques.
- Une string interessante doit etre croisee avec xrefs, call graph ou decompilation.

### Symboles

A quoi ca sert :

- Recuperer les noms de fonctions et variables exposes par le binaire.

Comment l'utiliser :

- Chercher `main`, des helpers nommes, des globals.
- Utiliser les symboles comme points d'entree de navigation.

Comment interpreter :

- Des noms de fonctions explicites font gagner enormement de temps.
- Des symboles `U` ou imports montrent les dependances externes.
- L'absence de symboles ne veut pas dire absence de structure ; seulement un binaire plus opaque.

Pieges frequents :

- Sur un binaire stripe, beaucoup de noms seront absents.
- Certains symboles d'environnement n'ont pas d'interet fonctionnel.

### Sections

A quoi ca sert :

- Comprendre la structure memoire et fichier du binaire.

Comment l'utiliser :

- Identifier `.text`, `.data`, `.rodata`, `.bss`, `.rsrc`, ou les segments Mach-O.
- Utiliser les sections pour filtrer strings et recherche.

Comment interpreter :

- `.text` correspond au code.
- `.rodata` contient souvent les strings et constantes.
- Une section inhabituelle ou tres dense peut meriter l'entropie.

Pieges frequents :

- Les noms de sections changent selon ELF, PE, Mach-O.
- Un binaire packe ou obfusque peut avoir des sections trompeuses.

### Entropie

A quoi ca sert :

- Mesurer si une zone ressemble a du code normal, du compresse, du chiffre, ou du bruit.

Comment l'utiliser :

- Regarder l'entropie globale.
- Comparer les sections entre elles.
- Zoomer sur les zones tres hautes.

Comment interpreter :

- Une zone tres haute peut signaler packing, chiffrement, donnees compressees ou shellcode.
- Une zone moyenne n'est pas forcement suspecte.
- Il faut toujours croiser avec sections, strings et imports.

Pieges frequents :

- Haute entropie ne veut pas dire malware.
- Certaines donnees legitimes ont une entropie elevee.

### Imports et exports

A quoi ca sert :

- Voir les APIs consommees et les fonctions exposees.

Comment l'utiliser :

- Chercher des imports reseau, systeme, crypto, processus, registry, memoire executable.
- Regarder les callsites par import.

Comment interpreter :

- Les imports dessinent tres vite la surface fonctionnelle du binaire.
- `system`, `CreateProcess`, `VirtualAlloc`, `connect`, `send`, `recv` sont de bons signaux d'audit.
- Les exports sont surtout utiles pour DLL, plugins, bibliotheques ou implants modulaires.

Pieges frequents :

- Un import dangereux n'est pas une preuve d'abus.
- Un binaire statique ou tres obfusque peut cacher cette surface.

### Infos binaire

A quoi ca sert :

- Resumer les metadonnees essentielles.

Comment l'utiliser :

- Toujours commencer par cette vue.
- Verifier format, architecture, bits, entry point, hashes, packers, imphash.

Comment interpreter :

- Le format et l'architecture expliquent deja quelles vues seront plus ou moins fortes.
- L'imphash est utile surtout sur PE pour de la comparaison ou du triage.
- Un packer detecte oriente vers une analyse plus prudente.

Pieges frequents :

- Le nom du fichier peut mentir ; les headers, eux, sont plus fiables.
- Le packer detecte reste souvent un indice, pas un verdict.

### Recherche binaire

A quoi ca sert :

- Chercher un motif textuel, hex ou regex dans les octets.

Comment l'utiliser :

- Rechercher une string vue ailleurs.
- Rechercher des constantes, magic bytes, opcodes, sequences.
- Limiter par zone ou sensibilite a la casse si besoin.

Comment interpreter :

- Tres utile pour retrouver rapidement un motif dans tout le fichier.
- Un resultat textuel peut etre rattache ensuite a une section ou une fonction.

Pieges frequents :

- Une occurence peut etre une simple donnee passive.
- Une regex trop large genere beaucoup de bruit.

### Ressources PE

A quoi ca sert :

- Explorer les ressources embarquees des executables Windows.

Comment l'utiliser :

- Ouvrir manifests, icones, version info, blobs de ressources.
- Chercher des scripts, configs, noms de services, UAC manifest.

Comment interpreter :

- Tres utile pour du PE : branding, privileges, traces d'installation, configuration.
- Un manifest peut expliquer certains comportements ou privileges.

Pieges frequents :

- Ne concerne pas les formats non-PE.
- Une ressource legitime peut paraitre "suspecte" hors contexte.

### Exceptions

A quoi ca sert :

- Lire les structures de gestion d'exceptions quand elles existent.

Comment l'utiliser :

- S'en servir surtout sur binaire C++ ou Windows.
- Croiser avec CFG et desassemblage quand le flux semble indirect.

Comment interpreter :

- Aide a expliquer des handlers, des unwind tables, ou certains chemins peu visibles.

Pieges frequents :

- Cette vue est plus specialisee et moins parlante sur tous les binaires.

### Donnees typees

A quoi ca sert :

- Reinterpreter une zone memoire comme types simples ou structures C.

Comment l'utiliser :

- Definir ou appliquer un type a un offset ou une adresse.
- Creer une structure quand tu reconnais un layout recurrent.
- Repropager cette connaissance vers d'autres vues.

Comment interpreter :

- Tres utile quand une zone binaire represente une table, une struct ou un blob de config.
- Un bon type rend le desassemblage et le pseudo-C plus compréhensibles.

Pieges frequents :

- Un mauvais type peut donner une lecture trompeuse.
- Il faut souvent iterer avant de converger vers le bon layout.

## AUDIT

Ces vues apparaissent seulement si le plugin `AUDIT` est installe et actif.

### Taint

A quoi ca sert :

- Suivre une propagation probable d'une source vers un sink.

Comment l'utiliser :

- Chercher des chaines comme entree utilisateur -> copie dangereuse -> execution.
- Utiliser cette vue pour prioriser les chemins a verifier.

Comment interpreter :

- Un chemin source -> sink est un excellent signal d'audit.
- Ce n'est pas une preuve absolue d'exploitabilite.
- Plus le chemin est court et lisible, plus il est convaincant.

Pieges frequents :

- L'analyse reste legere par rapport a un vrai dataflow engine.
- Certaines propagations implicites peuvent manquer.

### Vulnerabilites

A quoi ca sert :

- Signaler des APIs ou patterns dangereux.

Comment l'utiliser :

- Lire les alertes puis verifier les fonctions appelees.
- Croiser avec `Taint`, `Call Graph`, `Xrefs`, `Decompilateur`.

Comment interpreter :

- `strcpy`, `gets`, `sprintf`, `system` sont des signaux d'audit.
- Ce n'est pas une preuve qu'une faille est reellement atteignable.

Pieges frequents :

- Faux positifs si l'argument est constant ou controle.
- Faux negatifs si la faille ne passe pas par une API connue.

## MALWARE

Ces vues apparaissent seulement si le plugin `MALWARE` est installe et actif.

### Comportement

A quoi ca sert :

- Remonter des indices de reseau, crypto, persistance, exfiltration ou evasion.

Comment l'utiliser :

- Lancer cette vue apres les onglets `DATA`.
- Lire les indicateurs un par un.
- Revenir ensuite aux strings, imports, xrefs ou decompilation pour confirmer.

Comment interpreter :

- Le score est une somme heuristique, pas une probabilite de malware.
- Un score haut veut dire "beaucoup de motifs suspects ensemble".
- Une URL seule, une constante AES seule, ou une string VM seule restent ambigues.

Pieges frequents :

- Les faux positifs sont normaux.
- Il faut presenter cette vue comme `triage comportemental statique`.

### Anti-analyse

A quoi ca sert :

- Detecter des comportements qui compliquent l'analyse.

Comment l'utiliser :

- Regarder les strings VM, anti-debug, timing checks, imports specialises.
- Ouvrir ensuite la fonction ou la zone concernee.

Comment interpreter :

- Ce sont des techniques frequentes en malware, crackmes, protecteurs et logiciels anti-tamper.
- Leur presence n'est pas forcement malveillante, mais elle change le niveau de suspicion.

Pieges frequents :

- Une simple string `vmware` ne suffit pas a conclure.
- Il faut chercher l'usage reel de cette string.

### Detection YARA

A quoi ca sert :

- Matcher des regles basees sur des signatures.

Comment l'utiliser :

- Charger un jeu de regles adapte au contexte.
- Lire les matchs, tags, metas et strings responsables.

Comment interpreter :

- Un match YARA dit "ce binaire ressemble a cette regle", pas "j'ai prouve le comportement".
- Plus la regle est precise et contextualisee, plus le resultat est utile.

Pieges frequents :

- Une regle trop generique produit beaucoup de bruit.
- La qualite des regles conditionne fortement la qualite des resultats.

### Detection CAPA

A quoi ca sert :

- Identifier des capacites comportementales probables.

Comment l'utiliser :

- Lancer CAPA si l'environnement est supporte.
- Lire les capacites, puis ouvrir les fonctions ou preuves associees.

Comment interpreter :

- CAPA est tres utile pour dire "ce binaire semble savoir faire X".
- C'est puissant pour le triage malware et la comprehension rapide.

Pieges frequents :

- Tout depend des signatures et du support du format.
- Il faut valider les capacites sensibles par lecture du code.

### Deobfuscation

A quoi ca sert :

- Tenter de retrouver des strings cachees.

Comment l'utiliser :

- Lancer apres `Strings` quand tu soupconnes un XOR, du Base64 ou des stackstrings.
- Verifier ensuite si la string decodee est referencee dans le code.

Comment interpreter :

- Une string decodee plausible est un bon indice.
- Une string decodee seule doit etre contextualisee.

Pieges frequents :

- Cette vue peut produire du bruit ou des faux positifs lisibles.
- Une sortie "propre" doit etre validee par xrefs ou logique de code.

## OFFENSIF

Ces vues apparaissent seulement si le plugin `OFFENSIF` est installe et actif.

### ROP Gadgets

A quoi ca sert :

- Chercher des gadgets reutilisables dans une chaine ROP.

Comment l'utiliser :

- Filtrer par architecture, type de terminaison, motif utile.
- Ouvrir ensuite les gadgets vraiment exploitables en contexte.

Comment interpreter :

- Cette vue liste des candidats, pas une chaine exploitable complete.
- La presence d'un gadget utile ne veut pas dire vuln exploitable.

Pieges frequents :

- Les contraintes d'alignement, registres et memoire ne sont pas automatiquement satisfaites.

### FLIRT

A quoi ca sert :

- Reconnaitre des fonctions de bibliotheque par signatures.

Comment l'utiliser :

- Lancer la reconnaissance au debut ou au milieu de l'analyse.
- Utiliser les noms recuperes pour gagner du temps.

Comment interpreter :

- Une fonction reconnue comme standard est souvent moins prioritaire.
- L'identification reste probable, pas garantie a 100 %.

Pieges frequents :

- La couverture depend de la base de signatures disponible.

### Script Python

A quoi ca sert :

- Automatiser l'analyse et enchaîner plusieurs vues.

Comment l'utiliser :

- Importer directement les modules publics `backends.static.*` dans le panneau de script.
- Faire de petits scripts de triage, d'export ou de correlation.

Comment interpreter :

- Le scripting est ideal pour rendre une analyse reproductible.
- Tres utile pour des demos, audits repetes ou comparaisons.

Pieges frequents :

- Un mauvais script automatise vite de mauvaises hypotheses.
- Il faut garder la meme rigueur critique que dans l'interface.

## Comment presenter les resultats a l'oral

Formulation conseillee :

- `Cette vue montre...`
- `Ici, on observe...`
- `C'est un indice fort / un indice faible / un signal d'audit.`
- `Ca suggere que... mais il faut confirmer avec...`

Formulations a eviter :

- `Le binaire est forcement malveillant.`
- `La vue prouve a elle seule la vulnerabilite.`
- `Le pseudo-C est exactement le code source original.`

## Parcours de demo simple

Pour une demo rapide :

1. `Infos` pour situer le binaire.
2. `Strings` pour trouver les premiers indices.
3. `Fonctions` puis `Call Graph` pour la structure.
4. `Desassemblage` ou `Decompilateur` pour une fonction cle.
5. `Behavior` ou `Vulnerabilites` pour conclure avec une lecture securite.

## Resume en une phrase par vue

- `Infos` : qui est le binaire.
- `Sections` : comment il est organise.
- `Strings` : ce qu'il dit.
- `Symboles` : comment il nomme ses fonctions et donnees.
- `Recherche` : ou se trouve un motif.
- `Desassemblage` : ce que la machine execute.
- `CFG` : comment une fonction bifurque.
- `Call Graph` : qui appelle qui.
- `Fonctions` : quelles routines existent.
- `Decompilateur` : a quoi la logique ressemble en C.
- `Stack Frame` : comment la pile est utilisee.
- `Hex View` : quels octets sont vraiment presents.
- `Behavior` : quels comportements suspects ressortent.
- `Taint` : comment une donnee peut atteindre un sink.
- `Anti-analyse` : comment le binaire peut essayer de brouiller l'analyse.
- `YARA` : a quelle signature il ressemble.
- `CAPA` : quelles capacites il semble avoir.
- `Vulnerabilites` : quelles APIs dangereuses meritent un audit.
- `ROP` : quels gadgets existent potentiellement.
- `FLIRT` : quelles fonctions connues ont ete reconnues.
- `Deobfuscation` : quelles strings cachees peuvent etre revelees.
