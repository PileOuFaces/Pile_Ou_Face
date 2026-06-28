# Dynamic Backend Architecture

`backends.dynamic` regroupe tout le domaine d'analyse dynamique. La structure
separe le pipeline de traitement des moteurs runtime concrets pour que le
backend reste lisible quand de nouveaux moteurs ou enrichissements sont ajoutes.

## Organisation

- `core/` contient les contrats stables entre pipeline et runtimes:
  `ExecutionEngine`, `TraceConfigLike` et les types de trace partages.
- `pipeline/` contient l'orchestration de l'analyse, le modele canonique et les
  transformations qui construisent la sortie dynamique.
- `engine/` contient les implementations runtime concretes.
- `engine/unicorn/` contient le moteur actuel base sur Unicorn: chargement ELF,
  mapping memoire, hooks, registres, pile, syscalls et tracing.
- `tests/` contient les tests du domaine dynamique.

## Ajouter du code

- Nouveau moteur runtime: creer un sous-package dans `engine/`, par exemple
  `engine/qemu/`, et implementer `core.ExecutionEngine`.
- Nouvelle etape de pipeline: ajouter le module dans `pipeline/` et l'appeler
  depuis `pipeline/run_pipeline.py`.
- Nouveau modele canonique ou enrichissement: ajouter le module dans
  `pipeline/` si la donnee appartient a la sortie dynamique, ou dans un moteur
  seulement si elle depend fortement de ce runtime.

Les anciens modules plats de `backends.dynamic` restent des wrappers de
compatibilite temporaires. Le nouveau code doit importer depuis
`backends.dynamic.core`, `backends.dynamic.pipeline` ou
`backends.dynamic.engine`.
