# SPDX-License-Identifier: AGPL-3.0-only
# -----------------------------------------------------------------------------
# Small file I/O helpers for the tracing pipeline.
# load_code reads raw bytes from disk; is_elf checks the ELF magic header.
# -----------------------------------------------------------------------------

"""@file io.py
@brief Helpers d'I/O pour le traceur.

@details Lecture de blobs et detection ELF.
"""


def load_code(path: str) -> bytes:
    """@brief Charge un fichier binaire en bytes.
    @param path Chemin du fichier.
    @return Contenu binaire.
    """
    with open(path, "rb") as handle:
        return handle.read()


def is_elf(blob: bytes) -> bool:
    """@brief Indique si un blob est un ELF.
    @param blob Blob binaire.
    @return True si le magic ELF est present.
    """
    return len(blob) >= 4 and blob[:4] == b"\x7fELF"
