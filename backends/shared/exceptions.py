# SPDX-License-Identifier: AGPL-3.0-only
"""Exceptions custom pour le projet Pile ou Face.

Hiérarchie :
    PileOuFaceError          — base de toutes les erreurs projet
    ├── BinaryError          — erreurs liées au fichier binaire
    │   ├── BinaryNotFoundError
    │   └── BinaryParseError
    ├── DisassemblyError     — erreurs de désassemblage
    ├── CacheError           — erreurs du cache SQLite
    └── AnalysisError        — erreurs d'analyse (CFG, xrefs, etc.)

Usage:
    from backends.shared.exceptions import DisassemblyError, BinaryNotFoundError

    raise BinaryNotFoundError(f"Binary not found: {path}")
    raise DisassemblyError("Unsupported architecture")
"""

from __future__ import annotations


class PileOuFaceError(Exception):
    """Classe de base pour toutes les erreurs du projet Pile ou Face."""


# --- Erreurs binaire ---


class BinaryError(PileOuFaceError):
    """Erreur générique liée au fichier binaire."""


class BinaryNotFoundError(BinaryError):
    """Le fichier binaire spécifié n'existe pas ou n'est pas accessible."""


class BinaryParseError(BinaryError):
    """Impossible de parser le format du binaire (ELF/Mach-O/PE corrompu)."""


# --- Erreurs de désassemblage ---


class DisassemblyError(PileOuFaceError):
    """Erreur lors du désassemblage (architecture non supportée, section vide, etc.)."""


# --- Erreurs de cache ---


class CacheError(PileOuFaceError):
    """Erreur liée au cache SQLite (.pfdb)."""


class CacheCorruptedError(CacheError):
    """Le fichier cache SQLite est corrompu ou illisible."""


# --- Erreurs d'analyse ---


class AnalysisError(PileOuFaceError):
    """Erreur générique lors d'une analyse statique (CFG, xrefs, call graph, etc.)."""


class CFGError(AnalysisError):
    """Erreur lors de la construction du graphe de flot de contrôle."""


class XrefError(AnalysisError):
    """Erreur lors de l'extraction des cross-références."""


__all__ = [
    "PileOuFaceError",
    "BinaryError",
    "BinaryNotFoundError",
    "BinaryParseError",
    "DisassemblyError",
    "CacheError",
    "CacheCorruptedError",
    "AnalysisError",
    "CFGError",
    "XrefError",
]
