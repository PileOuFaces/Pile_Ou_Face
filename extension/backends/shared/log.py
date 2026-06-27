# SPDX-License-Identifier: AGPL-3.0-only
"""Configuration du logging pour le backend static.

Usage dans chaque module:
    from backends.static.log import get_logger
    logger = get_logger(__name__)

La variable d'environnement BINHOST_LOG_LEVEL contrôle le niveau de log.
Valeurs acceptées : DEBUG, INFO, WARNING (défaut), ERROR, CRITICAL.

Exemple:
    BINHOST_LOG_LEVEL=DEBUG python backends/static/disasm.py --binary foo.elf --output out.asm

Note: "BINHOST" est un préfixe neutre — renommer la constante _ENV_PREFIX dans license.py
      et mettre à jour ici quand le nom du produit est décidé.
"""

from __future__ import annotations

import logging
import os

# Version du format JSON de sortie (incrémentée lors de changements incompatibles)
FORMAT_VERSION = "1.0"

# Nom du générateur (inclus dans les métadonnées JSON)
GENERATOR = "pile-ou-face-static"

# Niveau de log par défaut (override avec BINHOST_LOG_LEVEL=DEBUG)
_DEFAULT_LEVEL = "WARNING"
_ENV_LEVEL = os.environ.get("BINHOST_LOG_LEVEL", _DEFAULT_LEVEL).upper()


def make_meta(module: str) -> dict:
    """Retourne les métadonnées standard à inclure dans les sorties JSON.

    Args:
        module: Nom du module générateur (ex: "disasm", "symbols").

    Returns:
        Dict ``{"version": "1.0", "generator": "pile-ou-face-static", "module": "..."}``
    """
    return {
        "version": FORMAT_VERSION,
        "generator": GENERATOR,
        "module": module,
    }


def get_logger(name: str) -> logging.Logger:
    """Retourne un logger pour le module donné.

    Args:
        name: Typiquement ``__name__``, ex: ``backends.static.disasm.disasm``

    Returns:
        Logger Python standard
    """
    return logging.getLogger(name)


def configure_logging(level: str | None = None) -> None:
    """Configure le logging pour une utilisation CLI.

    À appeler une seule fois depuis la fonction ``main()`` d'un module CLI.

    Args:
        level: Niveau de log (DEBUG, INFO, WARNING, ERROR). Utilise
               BINHOST_LOG_LEVEL si None, sinon WARNING par défaut.
    """
    resolved = (level or _ENV_LEVEL).upper()
    log_level = getattr(logging, resolved, logging.WARNING)
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s [%(name)s] %(message)s",
    )
