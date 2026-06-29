# Images Docker par décompilateur

Chaque décompilateur peut avoir sa propre image :

```text
docker/decompilers/
  retdec/Dockerfile
  ghidra/Dockerfile
  angr/Dockerfile
```

Build d'une image :

```bash
make decompiler-docker-build DECOMPILER=retdec
```

Le script `docker/decompilers/build.sh` existe encore pour compatibilité, mais
il délègue maintenant au `Makefile`, qui est la méthode canonique.

Tag attendu par défaut :

```text
pile-ou-face/decompiler-<id>:latest
```

Exemple :

```text
pile-ou-face/decompiler-retdec:latest
pile-ou-face/decompiler-ghidra:latest
pile-ou-face/decompiler-angr:latest
```

Pour un décompilateur custom déclaré dans `.pile-ou-face/decompilers.json`, il
faut renseigner `docker_image`, et si besoin `docker_command` /
`docker_full_command`.
