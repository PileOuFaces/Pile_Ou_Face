PYTHON ?= python3
VENV ?= backends/.venv
DECOMPILER ?= retdec
# Détection OS : Linux, Darwin (macOS), Windows
UNAME := $(shell $(PYTHON) -c "import platform; print(platform.system())" 2>/dev/null || echo Linux)
# Chemins BIN différenciés Windows/Unix
ifeq ($(UNAME),Windows)
  BIN := $(VENV)/Scripts
else
  BIN := $(VENV)/bin
endif
PIP := $(BIN)/pip
PY := $(BIN)/python

# --- Architecture Docker ---
# Détecte l'architecture hôte (arm64 sur Apple Silicon / Linux ARM, amd64 sinon)
# Peut être surchargé : make decompiler-docker-build PLATFORM=linux/amd64
HOST_ARCH := $(shell uname -m 2>/dev/null || echo x86_64)
ifeq ($(HOST_ARCH),arm64)
  DEFAULT_PLATFORM := linux/arm64
else ifeq ($(HOST_ARCH),aarch64)
  DEFAULT_PLATFORM := linux/arm64
else
  DEFAULT_PLATFORM := linux/amd64
endif
PLATFORM ?= $(DEFAULT_PLATFORM)
# Plateforme multi-arch pour buildx (toujours les deux)
MULTIARCH_PLATFORMS ?= linux/amd64,linux/arm64

EFFECTIVE_PLATFORM := $(PLATFORM)

.PHONY: help venv install install-dev pipeline lint format format-check test test-python test-python-coverage test-extension test-extension-coverage test-real-corpus test-coverage clean demo demo-similarity demo-suite demo-elf demo-push-ret capa-rules capa-docker \
        decompiler-docker-build decompiler-docker-list decompiler-docker-build-multiarch \
        decompiler-smoke-test decompilers-smoke-test-all \
        decompilers-docker-build decompilers-docker-list decompilers-docker-build-all \
        decompilers-docker-list-all decompilers-docker-build-multiarch-all buildx-setup \
        yara-check yara-test test-features \
        compiler-docker-build compiler-smoke-test compilers-docker-build-all compile demo-multiarch

help:
	@echo "Targets (Linux, macOS, Windows):"
	@echo "  venv       Create virtualenv in $(VENV)"
	@echo "  install    Install Python deps (requirements.txt)"
	@echo "  install-dev Install Python dev tools (Ruff + pytest)"
	@echo "  capa-rules Clone capa-rules (requis pour l'onglet Capa)"
	@echo "  demo       Compile les samples analyse/taint (demo_analysis.elf + test.elf)"
	@echo "  demo-similarity  Compile la paire reference/cible pour la vue Similarite"
	@echo "  demo-suite Compile demo + demo-similarity"
	@echo "  demo-elf   Compile un ELF Linux via Docker (pour Capa sur macOS/Windows)"
	@echo "  demo-push-ret  Binaire avec push+ret pour tester le CFG (x86_64 requis)"
	@echo "  capa-docker Run capa via Docker (contournement Mac ARM64)"
	@echo "  decompiler-docker-build DECOMPILER=retdec    Build l'image Docker d'un décompilateur (PLATFORM=$(EFFECTIVE_PLATFORM))"
	@echo "  decompiler-docker-list  DECOMPILER=retdec    Liste les décompilateurs dans l'image ciblée"
	@echo "  decompiler-docker-build-multiarch DECOMPILER=retdec  Build multi-arch (amd64+arm64) via buildx"
	@echo "  decompiler-smoke-test   DECOMPILER=ghidra   Smoke test fonctionnel d'une image"
	@echo "  decompilers-smoke-test-all                  Smoke test de toutes les images"
	@echo "  rop-smoke-test                              Smoke test ROP chain builder (angr)"
	@echo "  decompilers-docker-build-all                 Build toutes les images décompilateurs"
	@echo "  decompilers-docker-build-multiarch-all       Build multi-arch toutes les images (buildx)"
	@echo "  decompilers-docker-list-all                  Liste la dispo de tous les décompilateurs"
	@echo "  decompilers-docker-build                     Alias hérité → build retdec"
	@echo "  decompilers-docker-list                      Alias hérité → list retdec"
	@echo "  buildx-setup             Crée le builder buildx multi-arch (à faire une fois)"
	@echo "  compile SRC=file.c LANG=c TARGET=elf-arm64      Compile un fichier source"
	@echo "  demo-multiarch                                   Compile demo vers ELF x64/x86/arm64"
	@echo "  compiler-docker-build COMPILER=gcc-multiarch     Build l'image Docker d'un compilateur"
	@echo "  compiler-smoke-test   COMPILER=gcc-multiarch     Smoke test fonctionnel d'un compilateur"
	@echo "  compilers-docker-build-all                       Build toutes les images compilateurs"
	@echo ""
	@echo "  PLATFORM=$(PLATFORM) (auto-détecté depuis $(HOST_ARCH), effectif: $(EFFECTIVE_PLATFORM))"
	@echo "  RetDec supporte maintenant amd64 et arm64."
	@echo "  Surcharger si besoin: make decompiler-docker-build PLATFORM=linux/amd64"
	@echo "  yara-check Vérifie si YARA est installé (macOS: brew install yara)"
	@echo "  yara-test  Test YARA sur examples/demo_analysis.elf avec examples/test_rules.yar"
	@echo "  pipeline   Run full pipeline (use ARGS=\"...\")"
	@echo "  lint       Run Ruff on Python sources"
	@echo "  format     Format Python sources with Ruff"
	@echo "  format-check Check Python formatting without modifying files"
	@echo "  test-python Run all Python tests with pytest"
	@echo "  test-python-coverage Run Python tests with the coverage threshold"
	@echo "  test-extension Run extension tests"
	@echo "  test-extension-coverage Run extension tests with c8 thresholds"
	@echo "  test-real-corpus Run real-binary corpus tests and write metrics JSON"
	@echo "  test-coverage Run Python and extension coverage checks"
	@echo "  test       Run Ruff + all coverage thresholds"
	@echo "  test-features  Test des nouvelles features (push+ret, prelude, gaps)"
	@echo "  clean      Remove venv and caches"
	@echo ""
	@echo "Depuis backends/ : make -C .. demo-elf  ou  cd .. && make demo-elf"

yara-check:
	@command -v yara >/dev/null 2>&1 && echo "YARA installé: $$(yara -v 2>/dev/null || yara --version 2>/dev/null || echo OK)" || \
	(echo "YARA non installé. Sur macOS: brew install yara"; echo "Sur Linux: sudo apt install yara"; exit 1)

yara-test: yara-check demo
	@PYTHONPATH=. $(PYTHON) backends/static/yara_scan.py --binary examples/demo_analysis.elf --rules examples/test_rules.yar 2>/dev/null || \
	(echo "Exécutez: make demo puis testez depuis l'extension (onglet Détection > YARA > Parcourir > examples/test_rules.yar)"; exit 1)

capa-rules:
	@if [ ! -d backends/capa-rules ]; then \
		git clone --depth 1 https://github.com/mandiant/capa-rules backends/capa-rules; \
		echo "capa-rules cloné dans backends/capa-rules."; \
	else \
		echo "backends/capa-rules existe déjà."; \
	fi

demo:
	@if [ "$(UNAME)" = "Darwin" ]; then \
		gcc -arch x86_64 -O0 -g -fno-stack-protector -o examples/demo_analysis.elf examples/demo_analysis.c 2>/dev/null || \
		echo "gcc requis. Sur macOS: xcode-select --install"; \
		gcc -arch x86_64 -O0 -g -fno-stack-protector -o examples/test.elf examples/test.c 2>/dev/null || true; \
	elif [ "$(UNAME)" = "Windows" ]; then \
		gcc -O0 -g -fno-stack-protector -o examples/demo_analysis.elf examples/demo_analysis.c 2>/dev/null || \
		echo "gcc requis (MinGW/MSYS2). Sur Windows: installez MinGW ou utilisez 'make demo-elf' avec Docker."; \
		gcc -O0 -g -fno-stack-protector -o examples/test.elf examples/test.c 2>/dev/null || true; \
	else \
		gcc -O0 -g -fno-stack-protector -o examples/demo_analysis.elf examples/demo_analysis.c 2>/dev/null || \
		echo "gcc requis. Sur Linux: sudo apt install build-essential"; \
		gcc -O0 -g -fno-stack-protector -o examples/test.elf examples/test.c 2>/dev/null || true; \
	fi
	@if [ -f examples/demo_analysis.elf ]; then \
		echo "Binaire: examples/demo_analysis.elf — Ouvre-le dans Pile ou Face."; \
		[ -f examples/test.elf ] && echo "Compat:  examples/test.elf"; \
		[ "$(UNAME)" = "Darwin" ] && echo "  (Mach-O sur macOS; Capa ne supporte que ELF/PE. Pour Capa: make demo-elf)"; \
	fi

demo-similarity:
	@if [ "$(UNAME)" = "Darwin" ]; then \
		gcc -arch x86_64 -O0 -g -fno-stack-protector -o examples/demo_similarity_ref.elf examples/demo_similarity_ref.c 2>/dev/null || \
		echo "gcc requis. Sur macOS: xcode-select --install"; \
		gcc -arch x86_64 -O0 -g -fno-stack-protector -o examples/demo_similarity_target.elf examples/demo_similarity_target.c 2>/dev/null || true; \
	elif [ "$(UNAME)" = "Windows" ]; then \
		gcc -O0 -g -fno-stack-protector -o examples/demo_similarity_ref.elf examples/demo_similarity_ref.c 2>/dev/null || \
		echo "gcc requis (MinGW/MSYS2). Sur Windows: installez MinGW."; \
		gcc -O0 -g -fno-stack-protector -o examples/demo_similarity_target.elf examples/demo_similarity_target.c 2>/dev/null || true; \
	else \
		gcc -O0 -g -fno-stack-protector -o examples/demo_similarity_ref.elf examples/demo_similarity_ref.c 2>/dev/null || \
		echo "gcc requis. Sur Linux: sudo apt install build-essential"; \
		gcc -O0 -g -fno-stack-protector -o examples/demo_similarity_target.elf examples/demo_similarity_target.c 2>/dev/null || true; \
	fi
	@if [ -f examples/demo_similarity_ref.elf ] && [ -f examples/demo_similarity_target.elf ]; then \
		echo "Reference: examples/demo_similarity_ref.elf"; \
		echo "Cible:     examples/demo_similarity_target.elf"; \
		echo "UI: ouvre la cible, puis ajoute la reference dans OFFENSIF -> Similarite."; \
	fi

demo-suite: demo demo-similarity

demo-elf:
	@docker run --rm -v "$$(pwd):/src" -w /src gcc:latest gcc -O0 -g -fno-stack-protector -o examples/demo_analysis.elf examples/demo_analysis.c 2>/dev/null && \
		echo "ELF Linux: examples/demo_analysis.elf (compatible Capa)" || \
		echo "Docker requis. Installez Docker Desktop (macOS/Windows) ou docker.io (Linux)."

demo-push-ret:
	@echo "Compilation push+ret (x86_64)…"
	@PR_O=examples/push_ret_test.o; \
	if [ "$(UNAME)" = "Darwin" ]; then \
		gcc -arch x86_64 -c examples/push_ret_test.s -o $$PR_O 2>/dev/null || clang -arch x86_64 -c examples/push_ret_test.s -o $$PR_O 2>/dev/null; \
	else \
		gcc -c examples/push_ret_test.s -o $$PR_O 2>/dev/null; \
	fi; \
	if [ -f $$PR_O ]; then \
		if [ "$(UNAME)" = "Darwin" ]; then \
			gcc -arch x86_64 -O0 -g -fno-stack-protector -no-pie $$PR_O examples/demo_analysis.c -o examples/demo_push_ret.elf 2>/dev/null || \
			clang -arch x86_64 -O0 -g -fno-stack-protector -no-pie $$PR_O examples/demo_analysis.c -o examples/demo_push_ret.elf 2>/dev/null; \
		else \
			gcc -O0 -g -fno-stack-protector -no-pie $$PR_O examples/demo_analysis.c -o examples/demo_push_ret.elf 2>/dev/null; \
		fi; \
	fi; \
	if [ -f examples/demo_push_ret.elf ]; then \
		echo "Binaire: examples/demo_push_ret.elf (push+ret, x86_64)"; \
	else \
		echo "Échec. Sur macOS ARM64: gcc -arch x86_64 ou clang -arch x86_64 requis."; \
	fi

capa-docker:
	@$(MAKE) capa-rules 2>/dev/null || true
	@docker run --rm -v "$$(pwd):/work" -w /work python:3.12-slim bash -c "pip install -q flare-capa && capa -j /work/examples/demo_analysis.elf -r /work/backends/capa-rules" 2>/dev/null || \
		echo "Usage: make demo-elf && make capa-docker (Docker requis)"

buildx-setup:
	@echo "==> Création du builder buildx multi-arch 'pof-builder'…"
	@docker buildx inspect pof-builder > /dev/null 2>&1 \
		&& echo "  Builder 'pof-builder' existe déjà." \
		|| (docker buildx create --name pof-builder --driver docker-container --bootstrap && \
		    echo "  Builder 'pof-builder' créé avec succès.")
	@docker buildx use pof-builder
	@echo "  Pour vérifier: docker buildx ls"

decompiler-docker-build:
	@echo "==> Building pile-ou-face/decompiler-$(DECOMPILER):latest [$(EFFECTIVE_PLATFORM)]…"
	@docker build --platform $(EFFECTIVE_PLATFORM) \
		-f docker/decompilers/$(DECOMPILER)/Dockerfile \
		-t pile-ou-face/decompiler-$(DECOMPILER):latest \
		.

decompiler-docker-build-multiarch: buildx-setup
	@echo "==> Building multi-arch pile-ou-face/decompiler-$(DECOMPILER) [$(MULTIARCH_PLATFORMS)]…"
	@docker buildx build --platform $(MULTIARCH_PLATFORMS) \
		-f docker/decompilers/$(DECOMPILER)/Dockerfile \
		-t pile-ou-face/decompiler-$(DECOMPILER):latest \
		--push \
		. \
		|| (echo "" && echo "  Note: --push nécessite un registry (Docker Hub / GHCR)." && \
		    echo "  Pour un test local sans push: make decompiler-docker-build PLATFORM=linux/arm64")

decompiler-docker-list:
	@docker run --rm --platform $(EFFECTIVE_PLATFORM) pile-ou-face/decompiler-$(DECOMPILER):latest python -m backends.static.decompile --list --provider local

decompiler-smoke-test:
	@bash docker/decompilers/smoke-test.sh \
		pile-ou-face/decompiler-$(DECOMPILER):latest \
		$(DECOMPILER) \
		$(EFFECTIVE_PLATFORM)

decompilers-smoke-test-all:
	@echo "==> Smoke tests de toutes les images…"
	@for d in $(DECOMPILERS_ALL); do \
		_plat=$(PLATFORM); \
		[ "$$d" = "retdec" ] && _plat=linux/amd64; \
		echo ""; echo "==> Smoke test $$d [$$_plat]…"; \
		$(MAKE) decompiler-smoke-test DECOMPILER=$$d PLATFORM=$$_plat || echo "  ERREUR smoke $$d"; \
	done

rop-smoke-test:
	@echo "==> ROP chain builder smoke test (angr)"
	@docker run --rm pile-ou-face/decompiler-angr:latest \
		/opt/pof-venv/bin/python3 /opt/pof/test_rop_build.py

# Compile examples/test_rop.elf — ELF x86_64 volontairement vulnérable
# (Ubuntu 20.04 / glibc 2.31 pour conserver __libc_csu_init / pop rdi;ret)
demo-rop-elf:
	@echo "==> Compilation examples/test_rop.elf (x86_64, no PIE, no canary)"
	@docker run --rm --platform linux/amd64 \
		-v "$(CURDIR)/examples:/out" ubuntu:20.04 bash -c '\
		apt-get update -qq && apt-get install -y -qq gcc 2>/dev/null; \
		gcc -O0 -m64 -fno-stack-protector -no-pie \
		    -o /out/test_rop.elf /out/test_rop.c 2>&1 && echo "OK: examples/test_rop.elf"'

decompilers-docker-build:
	@echo "==> Alias hérité: utiliser plutôt 'make decompiler-docker-build DECOMPILER=retdec'"
	@$(MAKE) decompiler-docker-build DECOMPILER=retdec

decompilers-docker-list:
	@echo "==> Alias hérité: utiliser plutôt 'make decompiler-docker-list DECOMPILER=retdec'"
	@$(MAKE) decompiler-docker-list DECOMPILER=retdec

# Build toutes les images décompilateurs disponibles
DECOMPILERS_ALL ?= ghidra retdec angr

decompilers-docker-build-all:
	@echo "==> Build de toutes les images [$(PLATFORM)] …"
	@for d in $(DECOMPILERS_ALL); do \
		echo ""; \
		_plat=$(PLATFORM); \
		echo "==> Building pile-ou-face/decompiler-$$d:latest [$$_plat]…"; \
		$(MAKE) decompiler-docker-build DECOMPILER=$$d PLATFORM=$$_plat || echo "  ERREUR build $$d (continuer)"; \
	done
	@echo ""
	@echo "==> Build terminé pour : $(DECOMPILERS_ALL)"

decompilers-docker-build-multiarch-all: buildx-setup
	@echo "==> Build multi-arch de toutes les images [$(MULTIARCH_PLATFORMS)] …"
	@for d in $(DECOMPILERS_ALL); do \
		echo ""; \
		echo "==> Building multi-arch pile-ou-face/decompiler-$$d [$(MULTIARCH_PLATFORMS)]…"; \
		$(MAKE) decompiler-docker-build-multiarch DECOMPILER=$$d MULTIARCH_PLATFORMS=$(MULTIARCH_PLATFORMS) || echo "  ERREUR build multi-arch $$d (continuer)"; \
	done
	@echo ""
	@echo "==> Build multi-arch terminé pour : $(DECOMPILERS_ALL)"

decompilers-docker-list-all:
	@for d in $(DECOMPILERS_ALL); do \
		echo ""; \
		_plat=$(PLATFORM); \
		echo "==> [$$d] décompilateurs dans pile-ou-face/decompiler-$$d:latest [$$_plat]:"; \
		docker image inspect pile-ou-face/decompiler-$$d:latest > /dev/null 2>&1 \
			&& $(MAKE) decompiler-docker-list DECOMPILER=$$d PLATFORM=$$_plat \
			|| echo "  Image non buildée — lance: make decompiler-docker-build DECOMPILER=$$d"; \
	done

venv:
	$(PYTHON) -m venv $(VENV)

install: venv
	@if [ -f backends/requirements.txt ]; then \
		$(PIP) install -r backends/requirements.txt; \
	else \
		echo "backends/requirements.txt not found"; \
	fi
	@$(MAKE) capa-rules 2>/dev/null || true

install-dev: venv
	$(PIP) install -r backends/requirements-dev.txt

pipeline: venv
	$(PY) backends/dynamic/pipeline/run_pipeline.py $(ARGS)

lint:
	$(PY) -m ruff check .

format:
	$(PY) -m ruff format .

format-check:
	$(PY) -m ruff format --check .

test-python:
	PYTHONPATH=. $(PY) -m pytest

test-python-coverage:
	$(PY) -m coverage erase
	PYTHONPATH=. $(PY) -m coverage run -m pytest
	$(PY) -m coverage report
	$(PY) -m coverage xml

test-extension:
	cd extension && npm test

test-extension-coverage:
	cd extension && npm run test:coverage

test-real-corpus:
	@mkdir -p .pile-ou-face/test-artifacts
	POF_REAL_CORPUS_SUMMARY_JSON=.pile-ou-face/test-artifacts/real_binary_corpus_metrics.json \
		PYTHONPATH=. $(PY) -m pytest backends/static/tests/test_real_binary_corpus.py -q
	@echo "Résumé corpus: .pile-ou-face/test-artifacts/real_binary_corpus_metrics.json"

test-coverage: test-python-coverage test-extension-coverage

test: lint format-check test-coverage

test-features:
	@echo "=== Tests unitaires (push+ret, prelude, gaps) ==="
	@$(PYTHON) -m unittest backends.static.tests.test_cfg backends.static.tests.test_discover_functions -v
	@echo ""
	@echo "Test manuel avec binaire : make demo puis ouvrir dans Pile ou Face."
	@echo "Push+ret sur binaire : make demo-push-ret"

clean:
	rm -rf $(VENV) .coverage coverage.xml htmlcov .pytest_cache .ruff_cache extension/node_modules extension/coverage extension/.c8_output
	find . -type d \( -name __pycache__ -o -name .pytest_cache -o -name .ruff_cache \) -prune -exec rm -rf {} + 2>/dev/null || true

# ---------------------------------------------------------------------------
# Compilateurs — build / smoke test / compile
# ---------------------------------------------------------------------------
COMPILERS_ALL ?= gcc-multiarch rust go
COMPILER ?= gcc-multiarch

compiler-docker-build:
	@echo "==> Building pile-ou-face/compiler-$(COMPILER):latest [$(EFFECTIVE_PLATFORM)]..."
	@docker build --platform $(EFFECTIVE_PLATFORM) \
		-f docker/compilers/$(COMPILER)/Dockerfile \
		-t pile-ou-face/compiler-$(COMPILER):latest \
		.

compiler-smoke-test:
	@echo "==> Smoke test pile-ou-face/compiler-$(COMPILER):latest"
	@SRC=$$(mktemp /tmp/pof_test_XXXXXX.c); \
	echo 'int main(){return 0;}' > $$SRC; \
	docker run --rm \
		-v "$$SRC:/src/test.c:ro" \
		-v "/tmp:/out" \
		pile-ou-face/compiler-$(COMPILER):latest \
		python3 /opt/pof/compile.py --src /src/test.c --lang c --target elf-x64 --output /out/pof_smoke.elf \
	&& echo "  OK: compiler-$(COMPILER) smoke test passed" \
	|| echo "  ERREUR: compiler-$(COMPILER) smoke test failed"; \
	rm -f $$SRC /tmp/pof_smoke.elf

compilers-docker-build-all:
	@for c in $(COMPILERS_ALL); do \
		echo "==> Building compiler $$c..."; \
		$(MAKE) compiler-docker-build COMPILER=$$c || echo "  ERREUR build $$c"; \
	done

compile:
	@if [ -z "$(SRC)" ] || [ -z "$(LANG)" ] || [ -z "$(TARGET)" ]; then \
		echo "Usage: make compile SRC=file.c LANG=c TARGET=elf-x64"; exit 1; fi
	@PYTHONPATH=. $(PYTHON) -m backends.static.compile \
		--src "$(SRC)" --lang "$(LANG)" --target "$(TARGET)" \
		$(if $(OUTPUT),--output "$(OUTPUT)",)

demo-multiarch:
	@echo "==> Compilation multi-arch de examples/demo_analysis.c"
	@for t in elf-x64 elf-x86 elf-arm64; do \
		echo "  -> $$t"; \
		$(MAKE) compile SRC=examples/demo_analysis.c LANG=c TARGET=$$t \
			OUTPUT=examples/demo_analysis_$$t.elf 2>/dev/null \
			|| echo "    (skipped: no toolchain for $$t)"; \
	done
