# Matrices de capacites statiques

Ce document s'adresse aux mainteneurs. Il explique d'ou viennent les pastilles
de support de l'analyse statique et quels tests ajouter avant de changer un
niveau de capacite.

## Matrice backend par ISA

Source de verite :

- `extension/backends/static/binary/arch.py`
- `FEATURES`
- `FeatureSupport`
- `get_feature_support_matrix()`

Cette matrice decrit le support par adaptateur d'architecture. Les adaptateurs
avec semantique CFG/Call Graph sont actuellement :

- `x86` : x86 / x86-64 ;
- `arm32` : ARM / Thumb ;
- `arm64` : AArch64 ;
- `mips` : MIPS32 / MIPS64 ;
- `ppc` : PowerPC 32 / 64 ;
- `sparc` : SPARC / SPARCV9 ;
- `riscv` : RISC-V 32 / 64 ;
- `sysz` : SystemZ / s390x ;
- `bpf` : BPF ;
- `wasm` : WebAssembly ;
- `m68k` : M68K ;
- `sh` : SuperH ;
- `tricore` : TriCore.

Les autres profils Capstone raw peuvent rester `disasm-only` ou `unsupported`
pour les features semantiques tant qu'aucun adaptateur ISA n'existe. Cela
evite de presenter un CFG/Call Graph vide comme un resultat valide.

La matrice expose les features suivantes :

- `disasm`
- `discover_functions`
- `cfg`
- `xrefs`
- `call_graph`
- `stack_frame`
- `calling_convention`

Niveaux autorises :

- `full` : le chemin de production est implemente et couvert pour cette famille
  d'ISA.
- `partial` : le support est utile, mais certaines recuperations avancees
  peuvent etre incompletes.
- `disasm-only` : Capstone sait decoder les octets, mais l'analyse semantique
  n'est pas fiable.
- `unsupported` : la feature ne doit pas etre exposee comme utilisable.

Avant de promouvoir une feature backend de `unsupported` ou `disasm-only` vers
`partial`/`full`, il faut ajouter ou mettre a jour des tests qui executent la
vraie pipeline pour cette architecture. Pour la partie Functions, le garde-fou
est :

- `extension/backends/static/tests/test_function_arch_matrix.py`

Ce test relie la matrice aux fixtures raw Capstone et verifie que :

- la decouverte de fonctions retrouve la fonction d'entree et la cible ;
- le CFG contient l'edge d'appel direct attendu ;
- le call graph contient l'edge de fonction attendu.

## Matrice des onglets raw

Source de verite :

- `extension/front/shared/rawTabCapabilities.js`

Cette matrice decrit les onglets statiques pour les blobs bruts/shellcodes, pas
pour les binaires natifs ELF/PE/Mach-O.

Niveaux actuels :

- `full` : `disasm`, `discovered`, `cfg`, `callgraph`, `hex`, `sections`,
  `info`, `strings`, `recherche`, `typed_data`, `script`
- `limited` : `symbols`, `imports`, `detection`, `deobfuscate`, `rop`
- `unsupported` : `func_similarity`, `decompile`, `stack`, `pe_resources`,
  `exceptions`, `taint`, `behavior`, `anti_analysis`, `vulns`, `flirt`,
  `bindiff`

Le garde-fou est :

- `extension/front/tests/rawTabCapabilities.test.ts`

Ne pas passer un onglet raw en `full` uniquement parce qu'un backend pour binaire
natif supporte une feature similaire. Exemple : `stack_frame` est supporte dans
la matrice backend par ISA, mais l'analyseur de stack statique actuel depend de
LIEF pour parser un binaire structure. L'onglet raw `stack` reste donc
`unsupported` tant qu'un chemin stack raw specifique n'existe pas.

## Regle de changement

Chaque changement de niveau de capacite doit avoir l'un de ces deux elements :

- un test qui prouve que la feature fonctionne sur l'architecture ou l'onglet
  raw annonce ;
- ou une note claire `limited`/`unsupported` qui explique la dependance manquante.

Si une capacite depend d'un plugin premium, le host public doit rester en
`limited` sauf si le chemin public peut prouver le fonctionnement end-to-end sans
ce plugin.
