# Décompilateurs — Guide complet

Ce guide couvre tout : comment fonctionne le moteur de décompilation, comment brancher n'importe quel outil (sur la machine ou via Docker), comment le mode Auto sélectionne le meilleur résultat, et comment créer ses propres images pour x86 ou ARM64.

---

## Architecture du moteur

Pile ou Face ne contient aucun décompilateur intégré. Tout passe par un fichier de configuration unique :

```
<workspaceStorage>/<workspace-id>/PileOuFaces.stack-visualizer/decompilers.json
```

Dans l'extension VS Code, ce fichier est placé dans `context.storageUri` puis
passé au backend via `DECOMPILERS_CONFIG`. Le dossier projet `.pile-ou-face/`
n'est pas migre ni lu comme chemin de reference par l'extension.

Le moteur (`backends/static/decompile/decompile.py`) lit ce fichier, détecte ce qui est disponible, exécute les outils, parse leur sortie, score le résultat, et choisit le meilleur en mode Auto.

```
decompilers.json
      │
      ▼
_load_decompilers()          ← parse + normalise le JSON
      │
      ▼
_is_decompiler_available()   ← detect / detect_cmd / docker
      │
      ├── provider=local  → _run_custom_decompiler()
      ├── provider=docker → _run_custom_decompiler_in_docker()
      └── provider=auto   → local d'abord, docker en fallback
                                │
                                ▼
                    _parse_external_decompiler_output()
                                │
                                ▼
                    _score_decompile_code()   ← mode Auto uniquement
                                │
                                ▼
                    _select_best_function_candidate()
```

---

## Le fichier decompilers.json — référence complète

```json
{
  "decompilers": {
    "<id>": {
      "label":               "Nom affiché dans l'interface",
      "command":             ["outil", "--args", "{binary}", "{addr}"],
      "full_command":        ["outil", "--all", "{binary}"],
      "fallback_command":    ["outil", "--fallback", "{binary}", "{addr}"],
      "detect":              "nom-executable-dans-PATH",
      "detect_cmd":          ["outil", "--version"],
      "docker_image":        "registry/image:tag",
      "docker_command":      ["outil", "{binary}", "{addr}"],
      "docker_full_command": ["outil", "--all", "{binary}"],
      "docker_extra_args":   ["--memory", "4g"],
      "output_format":       "json",
      "timeout":             120,
      "env":                 { "GHIDRA_INSTALL_DIR": "/opt/ghidra" },
      "network":             "none",
      "quality_bias":        10,
      "precision_bias":      5
    }
  }
}
```

### Tous les champs

| Champ | Type | Description |
|---|---|---|
| `label` | string | Nom affiché dans l'UI. Défaut : l'identifiant. |
| `command` | array | Commande locale pour décompiler **une fonction**. |
| `full_command` | array | Commande locale pour décompiler **le binaire entier**. Si absent, `command` est utilisé. |
| `fallback_command` | array | Commande de secours si `command` ne produit rien (ex : `pdc` → `pdf`). Uniquement pour le mode fonction, pas full. |
| `detect` | string | Exécutable à chercher dans `PATH` via `shutil.which`. Si trouvé → local disponible. |
| `detect_cmd` | array | Commande à lancer pour vérifier la disponibilité (returncode 0 = disponible). Prioritaire sur `detect`. Utile pour les plugins (ex : rz-ghidra). |
| `docker_image` | string | Image Docker à utiliser. |
| `docker_command` | array | Commande exécutée dans le container pour une fonction. |
| `docker_full_command` | array | Commande dans le container pour le binaire entier. |
| `docker_extra_args` | array | Arguments supplémentaires passés à `docker run` (ex : `--memory 4g`, `--cpus 2`). |
| `output_format` | string | `json` (défaut), `c`, ou `text`. Voir section parsing. |
| `timeout` | number | Timeout en secondes. Défaut : 120 (fonction), 300 (binaire entier). |
| `env` | object | Variables d'environnement injectées dans la commande locale. |
| `network` | string | Réseau Docker : `none` (défaut), `bridge`, `host`. |
| `quality_bias` | number | Bonus de score ajouté en mode Auto normal (voir section scoring). |
| `precision_bias` | number | Bonus de score ajouté en mode Auto précision. |

### Tokens dans les commandes

Ces tokens sont remplacés automatiquement à l'exécution dans chaque élément du tableau. Voir la [référence complète des tokens](#tokens-de-commande) dans la section Fonctionnalités avancées.

| Token | Valeur |
|---|---|
| `{binary}` | Chemin absolu du binaire analysé |
| `{addr}` | Adresse hexadécimale de la fonction (ex : `0x401000`) |
| `{func_name}` | Nom de la fonction si connu |
| `{mode}` | `function` ou `full` |
| `{out}` | Chemin vers un fichier de sortie temporaire (si l'outil écrit un fichier plutôt que stdout) |
| `{arch}` | Architecture détectée : `x86`, `x86_64`, `arm`, `arm64`, `mips`, `mips64`, `ppc`, `ppc64`, `unknown` |
| `{bitness}` | `"32"` ou `"64"` |
| `{format}` | Format du binaire : `elf`, `pe`, `macho`, `raw` |
| `{binary_b64}` | Contenu du binaire encodé en base64 (endpoints HTTP uniquement) |
| `{root_dir}` | Chemin absolu de la racine du projet |

---

## Fonctionnalités avancées

### Tokens de commande

Tous les champs `command`, `docker_command`, `full_command`, `docker_full_command` et `body_template` supportent les tokens suivants :

| Token | Valeur injectée |
|---|---|
| `{binary}` | Chemin absolu du binaire à analyser |
| `{addr}` | Adresse de la fonction (ex: `0x401000`) |
| `{func_name}` | Nom de la fonction si connu |
| `{mode}` | `"function"` ou `"full"` |
| `{out}` | Chemin du fichier de sortie temporaire |
| `{arch}` | Architecture détectée : `x86`, `x86_64`, `arm`, `arm64`, `mips`, `mips64`, `ppc`, `ppc64`, `unknown` |
| `{bitness}` | `"32"` ou `"64"` |
| `{format}` | Format du binaire : `elf`, `pe`, `macho`, `raw` |
| `{binary_b64}` | Contenu du binaire encodé en base64 (endpoints HTTP uniquement) |
| `{root_dir}` | Chemin absolu de la racine du projet |

### Nettoyage de sortie (`output_filter`)

Pour supprimer le bruit spécifique à un outil sans modifier le moteur :

```json
"mytool": {
  "output_filter": ["^\\[\\*\\]", "^DEBUG:", "^\\s*;.*"]
}
```

Chaque entrée est une regex Python. Les lignes correspondantes sont supprimées avant le parsing. Les patterns doivent être des expressions régulières Python valides — une regex invalide provoque une erreur lors de la décompilation.

### Endpoint HTTP/REST (`endpoint`)

Pour connecter un service distant ou un serveur local sans passer par un subprocess :

```json
"ida_server": {
  "label": "IDA Pro Server",
  "endpoint": "http://localhost:9090/decompile",
  "method": "POST",
  "headers": {"Content-Type": "application/json"},
  "body_template": "{\"binary_b64\": \"{binary_b64}\", \"addr\": \"{addr}\"}",
  "output_format": "json",
  "timeout": 60
}
```

Le service doit retourner du JSON compatible avec le format de sortie du moteur (`{"addr": "0x...", "code": "...", "error": null}`). Aucune dépendance externe — uniquement `urllib.request` (stdlib Python).

### Authentification HTTP (`auth`)

Les credentials sont lus depuis des variables d'environnement — jamais hardcodés dans `decompilers.json` :

```json
"secured_service": {
  "endpoint": "https://api.example.com/decompile",
  "auth": {
    "type": "bearer",
    "token_env": "MY_SERVICE_TOKEN"
  }
}
```

Types supportés :

| Type | Header injecté | Variables requises |
|---|---|---|
| `"bearer"` | `Authorization: Bearer $token_env` | `token_env` |
| `"api_key"` | `$header: $token_env` (défaut: `X-API-Key`) | `token_env`, optionnel: `header` |
| `"basic"` | `Authorization: Basic base64($user:$password)` | `user_env`, `password_env` |

Si une variable d'environnement est absente, la décompilation retourne une erreur explicite contenant le nom de la variable manquante.

---

## Formats de sortie

### `output_format: "json"` (défaut)

L'outil écrit du JSON sur stdout. Deux formes acceptées :

**Dict (une fonction) :**
```json
{ "addr": "0x401000", "code": "int main() { ... }", "error": null }
```

**Liste (plusieurs fonctions) :**
```json
[
  { "addr": "0x401000", "name": "main",   "code": "int main() { ... }" },
  { "addr": "0x401100", "name": "helper", "code": "void helper() { ... }" }
]
```

### `output_format: "c"`

L'outil écrit du pseudo-C brut sur stdout (ou stderr selon la version). Le moteur :

1. Filtre les lignes de bruit : `VERBOSE:`, `ERROR:`, `WARNING:`, codes ANSI `\x1b[...`, `rz_*`
2. En mode fonction : retourne le texte brut filtré dans `code`
3. En mode full : parse les blocs via `_parse_c_like_function_blocks` — détecte les signatures `type nom(args) {` et extrait les adresses depuis les commentaires `// address: 0x...`

### `output_format: "text"`

Texte brut retourné tel quel dans `code`. Utile pour du désassemblage formaté (`pdf`, objdump, etc.).

---

## Mode Auto et scoring

Quand aucun décompilateur n'est spécifié (mode Auto), le moteur essaie **tous les décompilateurs disponibles dans l'ordre du JSON**, score chaque résultat, et retourne le meilleur.

### Ordre de priorité

L'ordre de déclaration dans `decompilers.json` = ordre d'essai. Déclare du meilleur au moins bon.

### Algorithme de sélection

```
pour chaque décompilateur dans l'ordre du JSON :
    résultat = run(décompilateur, binary, addr)
    si résultat.code non vide :
        score = _score_decompile_code(résultat.code, décompilateur)
        ajouter à la liste des candidats

retourner le candidat avec le score le plus élevé
```

### Calcul du score (`_score_decompile_code`)

**Points positifs :**

| Critère | Poids | Plafond |
|---|---|---|
| Lignes de code non vides | ×1 | 90 |
| Appels de fonctions détectés | ×4 | 24 |
| Structures de contrôle (`if/while/for/switch/return`) | ×5 | 30 |
| Type hints C (`int/char/uint32_t/...`) | ×2 | 16 |
| Casts explicites `(type)` | ×1 | 8 |
| Appels attendus retrouvés | ×12 | illimité |

**Points négatifs :**

| Critère | Poids | Plafond |
|---|---|---|
| Variables placeholder `local_XX/var_XX/DAT_XXXX` | ×2 | 24 |
| `goto` | ×3 | 12 |
| Résidus bas niveau `push/pop/rax/qword/CODE XREF` | ×2 | 30 |
| `// WARNING:` dans le code | ×8 | 24 |

**Bonus fixe :** `quality_bias` (mode normal) ou `precision_bias` (mode précision) déclaré dans le JSON, ajouté directement.

**Mode précision** (`quality=precision`) : plafonds plus bas, pénalités plus fortes sur les placeholders et les gotos — favorise la lisibilité sur le volume.

### Ajuster le scoring avec `quality_bias`

Si un décompilateur produit systématiquement de bons résultats mais est sous-classé (ex : son pseudo-C utilise des noms non-conventionnels que le scorer pénalise), augmente son bias :

```json
"mon-outil": {
  "quality_bias": 15,
  "precision_bias": 20
}
```

Commence à 0 et monte par paliers de 5 jusqu'à ce que le mode Auto choisisse régulièrement ton outil quand il produit le meilleur résultat. Les métriques brutes sont exposées dans le champ `_quality_details` de la réponse JSON pour débugger.

---

## Exemples complets par décompilateur

### Ghidra — Docker

Builder l'image depuis la racine du projet :

```bash
make decompiler-docker-build DECOMPILER=ghidra
# → pile-ou-face/decompiler-ghidra:latest
```

Configuration dans `context.storageUri/decompilers.json` :

```json
{
  "decompilers": {
    "ghidra": {
      "label": "Ghidra",
      "docker_image": "pile-ou-face/decompiler-ghidra:latest",
      "docker_command": [
        "/opt/pof-venv/bin/python", "-m", "backends.static.decompile",
        "--decompiler", "ghidra",
        "--binary", "{binary}",
        "--addr", "{addr}",
        "--provider", "local"
      ],
      "docker_full_command": [
        "/opt/pof-venv/bin/python", "-m", "backends.static.decompile",
        "--decompiler", "ghidra",
        "--binary", "{binary}",
        "--full",
        "--provider", "local"
      ],
      "docker_extra_args": ["--platform", "linux/amd64"],
      "output_format": "json",
      "quality_bias": 20,
      "precision_bias": 25
    }
  }
}
```

Test rapide :

```bash
docker run --rm --platform linux/amd64 \
  -v /chemin/vers/mon/binaire:/input/binaire:ro \
  pile-ou-face/decompiler-ghidra:latest \
  /opt/pof-venv/bin/python -m backends.static.decompile \
    --decompiler ghidra \
    --binary /input/binaire \
    --addr 0x401000 \
    --provider local
```

**Contenu de l'image :** Ubuntu 24.04, JDK 21, Ghidra 12, PyGhidra 3. Décompilation via `pyghidra.run_script()` + script Python 3 (`script.py`).

**Plateformes :** `linux/amd64` natif. Sur arm64, Docker/OrbStack émule via Rosetta — même comportement que RetDec. `docker_extra_args: ["--platform", "linux/amd64"]` obligatoire sur Apple Silicon.

---

### RetDec — Docker

```bash
make decompiler-docker-build DECOMPILER=retdec
# → pile-ou-face/decompiler-retdec:latest
```

```json
{
  "decompilers": {
    "retdec": {
      "label": "RetDec",
      "docker_image": "pile-ou-face/decompiler-retdec:latest",
      "docker_command": [
        "python", "-m", "backends.static.decompile",
        "--decompiler", "retdec",
        "--binary", "{binary}",
        "--addr", "{addr}",
        "--provider", "local"
      ],
      "output_format": "json",
      "quality_bias": 10,
      "precision_bias": 8
    }
  }
}
```

Test rapide :

```bash
docker run --rm \
  -v /chemin/vers/mon/binaire:/input/binaire:ro \
  pile-ou-face/decompiler-retdec:latest \
  python -m backends.static.decompile \
    --decompiler retdec \
    --binary /input/binaire \
    --addr 0x401000 \
    --provider local
```

**Contenu de l'image :** Ubuntu 22.04, RetDec v5 pré-compilé pour `linux/amd64`.

**Plateformes :** `linux/amd64` natif. Sur arm64, Docker/OrbStack émule automatiquement via QEMU — premier run ~30s plus lent.

---

### Rizin — local (macOS / Linux)

```bash
# macOS
brew install rizin

# Ubuntu/Debian
sudo apt install rizin
```

```json
{
  "decompilers": {
    "rizin": {
      "label": "rizin",
      "detect": "rizin",
      "command": [
        "rizin", "-q",
        "-e", "scr.color=0",
        "-e", "log.level=5",
        "-c", "aa; s {addr}; af; pdc",
        "{binary}"
      ],
      "fallback_command": [
        "rizin", "-q",
        "-e", "scr.color=0",
        "-e", "log.level=5",
        "-c", "aa; s {addr}; af; pdf",
        "{binary}"
      ],
      "full_command": [
        "rizin", "-q",
        "-e", "scr.color=0",
        "-e", "log.level=5",
        "-c", "aaa; pdc @@f",
        "{binary}"
      ],
      "output_format": "c",
      "quality_bias": 5
    }
  }
}
```

**Limitations :** `pdc` (pseudo-C natif) ne produit rien sur les binaires Mach-O ARM64 (Apple Silicon, Obj-C/Swift). Le `fallback_command` prend alors le relais et retourne le désassemblage via `pdf`. Pour du vrai pseudo-C sur Mach-O, utilise Ghidra ou RetDec via Docker.

**Plugin rz-ghidra (optionnel) :** si installé, ajoute une seconde entrée qui utilise `pdg` (qualité Ghidra) :

```json
"rz-ghidra": {
  "label": "rizin (rz-ghidra)",
  "detect_cmd": ["rizin", "-q", "-c", "pdg??", "/dev/null"],
  "command": [
    "rizin", "-q", "-e", "scr.color=0", "-e", "log.level=5",
    "-c", "aa; s {addr}; af; pdg", "{binary}"
  ],
  "fallback_command": [
    "rizin", "-q", "-e", "scr.color=0", "-e", "log.level=5",
    "-c", "aa; s {addr}; af; pdc", "{binary}"
  ],
  "full_command": [
    "rizin", "-q", "-e", "scr.color=0", "-e", "log.level=5",
    "-c", "aaa; pdg @@f", "{binary}"
  ],
  "output_format": "c",
  "quality_bias": 15,
  "precision_bias": 18
}
```

---

### Angr — Docker

```bash
make decompiler-docker-build DECOMPILER=angr
# → pile-ou-face/decompiler-angr:latest
```

```json
"angr": {
  "label": "Angr",
  "docker_image": "pile-ou-face/decompiler-angr:latest",
  "docker_command": [
    "python", "-m", "backends.static.decompile",
    "--decompiler", "angr",
    "--binary", "{binary}",
    "--addr", "{addr}",
    "--provider", "local"
  ],
  "output_format": "json",
  "timeout": 180,
  "quality_bias": 8
}
```

**Plateformes :** `linux/amd64` et `linux/arm64` natifs.

---

## Créer sa propre image Docker

### Structure minimale

L'image reçoit le binaire monté en lecture seule dans `/input/` et doit écrire le résultat sur stdout (JSON, C, ou texte).

**Dockerfile minimal :**

```dockerfile
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y mon-outil && rm -rf /var/lib/apt/lists/*
```

**Builder pour une architecture précise :**

```bash
# x86_64 uniquement
docker build --platform linux/amd64 -t mon-outil:amd64 .

# ARM64 uniquement
docker build --platform linux/arm64 -t mon-outil:arm64 .

# Multi-arch (buildx, nécessite un builder configuré)
docker buildx build --platform linux/amd64,linux/arm64 \
  -t mon-registry/mon-outil:latest --push .
```

**Sur une machine ARM64 avec une image x86 uniquement :**

```bash
export POF_DOCKER_PLATFORM=linux/amd64
```

Docker/OrbStack gérera l'émulation QEMU automatiquement.

**Configuration :**

```json
{
  "decompilers": {
    "mon-outil": {
      "label": "Mon outil (Docker)",
      "docker_image": "mon-registry/mon-outil:latest",
      "docker_command": [
        "mon-outil", "--binary", "{binary}", "--addr", "{addr}"
      ],
      "docker_extra_args": ["--memory", "4g", "--cpus", "2"],
      "output_format": "c",
      "timeout": 180,
      "network": "none"
    }
  }
}
```

### Wrapper Python si l'outil n'a pas de CLI propre

```python
#!/usr/bin/env python3
# /usr/local/bin/wrapper.py — inclus dans l'image
import sys, json, subprocess

binary = sys.argv[sys.argv.index('--binary') + 1]
addr   = sys.argv[sys.argv.index('--addr')   + 1]

result = subprocess.run(
    ['mon-outil-interne', binary, addr],
    capture_output=True, text=True
)

print(json.dumps({
    "addr":  addr,
    "code":  result.stdout,
    "error": result.stderr if result.returncode != 0 else None
}))
```

Dockerfile :
```dockerfile
FROM ubuntu:24.04
COPY wrapper.py /usr/local/bin/wrapper.py
RUN chmod +x /usr/local/bin/wrapper.py
```

JSON :
```json
"docker_command": [
  "python3", "/usr/local/bin/wrapper.py",
  "--binary", "{binary}", "--addr", "{addr}"
]
```

---

## Configuration complète — exemple avec tout

```json
{
  "decompilers": {
    "ghidra": {
      "label": "Ghidra",
      "docker_image": "pile-ou-face/decompiler-ghidra:latest",
      "docker_command": ["/opt/pof-venv/bin/python", "-m", "backends.static.decompile", "--decompiler", "ghidra", "--binary", "{binary}", "--addr", "{addr}", "--provider", "local"],
      "docker_full_command": ["/opt/pof-venv/bin/python", "-m", "backends.static.decompile", "--decompiler", "ghidra", "--binary", "{binary}", "--full", "--provider", "local"],
      "docker_extra_args": ["--platform", "linux/amd64"],
      "output_format": "json",
      "quality_bias": 20,
      "precision_bias": 25
    },
    "retdec": {
      "label": "RetDec",
      "docker_image": "pile-ou-face/decompiler-retdec:latest",
      "docker_command": ["python", "-m", "backends.static.decompile", "--decompiler", "retdec", "--binary", "{binary}", "--addr", "{addr}", "--provider", "local"],
      "output_format": "json",
      "quality_bias": 10,
      "precision_bias": 8
    },
    "rizin": {
      "label": "rizin",
      "detect": "rizin",
      "command": ["rizin", "-q", "-e", "scr.color=0", "-e", "log.level=5", "-c", "aa; s {addr}; af; pdc", "{binary}"],
      "fallback_command": ["rizin", "-q", "-e", "scr.color=0", "-e", "log.level=5", "-c", "aa; s {addr}; af; pdf", "{binary}"],
      "full_command": ["rizin", "-q", "-e", "scr.color=0", "-e", "log.level=5", "-c", "aaa; pdc @@f", "{binary}"],
      "output_format": "c",
      "quality_bias": 5
    }
  }
}
```

---

## Diagnostiquer un problème

**Le décompilateur s'affiche comme indisponible :**

```bash
# Docker
docker images | grep pile-ou-face

# Local — vérifier le PATH
which rizin

# detect_cmd — tester manuellement
rizin -q -c "pdg??" /dev/null
echo $?   # 0 = disponible, autre = plugin absent
```

**"aucune sortie" après décompilation :**

Lance la commande directement et observe stdout + stderr séparément :

```bash
rizin -q -e scr.color=0 -e log.level=5 \
  -c "aa; s 0x401000; af; pdc" /chemin/binaire 2>/tmp/rizin_err.txt
cat /tmp/rizin_err.txt
```

Si stdout vide et stderr contient du code C → le moteur gère ça automatiquement (fallback stderr → stdout). Si les deux sont vides → `pdc` ne supporte pas ce format binaire, utilise Ghidra.

**Docker "permission denied" sur le binaire :**

Le binaire est monté en lecture seule dans `/input/`. Si l'outil crée des fichiers temporaires dans le même dossier, ajoute `--tmpfs /tmp` dans `docker_extra_args`.

**Voir les logs complets :**

VSCode → **Affichage** → **Sortie** → **Pile ou Face**
