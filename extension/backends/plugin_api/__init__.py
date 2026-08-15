# SPDX-License-Identifier: AGPL-3.0-only
"""Stable Python import surface for Pile ou Face plugins.

Plugins MUST import from this module — never from backends.shared.*
or backends.static.* directly. If host internals move, only this file
changes; plugins are untouched.

Stable symbols (never rename or remove without a major version bump):

Logging
-------
get_logger(name) -> logging.Logger
configure_logging(level=None) -> None

Binary utilities
----------------
build_offset_to_vaddr(binary_path) -> dict[int, int]

Architecture detection
----------------------
ArchInfo            — dataclass: arch, bits, endian, ...
FeatureSupport      — dataclass: level, description
detect_binary_arch_from_path(binary_path) -> ArchInfo | None
get_feature_support(arch, feature) -> FeatureSupport
get_raw_arch_info(raw_arch, endian=None) -> ArchInfo | None

AI follow-up
------------
request_ai_followup(prompt, context, capability) -> dict
"""

from __future__ import annotations

from typing import Any

from backends.shared.log import configure_logging, get_logger
from backends.shared.utils import build_offset_to_vaddr
from backends.static.binary.arch import (
    ArchInfo,
    FeatureSupport,
    detect_binary_arch_from_path,
    get_feature_support,
    get_raw_arch_info,
)

AI_FOLLOWUP_VERSION = 1


def request_ai_followup(
    prompt: str,
    context: dict[str, Any],
    capability: str,
) -> dict[str, dict[str, Any]]:
    """Build the stable, host-owned envelope for one bounded AI follow-up.

    The host validates sizes, capability ownership and consent before contacting
    its configured provider. Provider credentials never enter this payload.
    """
    prompt_text = str(prompt or "").strip()
    capability_name = str(capability or "").strip()
    if not prompt_text:
        raise ValueError("prompt vide")
    if not capability_name:
        raise ValueError("capability vide")
    if not isinstance(context, dict):
        raise TypeError("context doit être un objet JSON")
    return {
        "ai_followup": {
            "version": AI_FOLLOWUP_VERSION,
            "prompt": prompt_text,
            "context": dict(context),
            "capability": capability_name,
        }
    }


__all__ = [
    # Logging
    "get_logger",
    "configure_logging",
    # Binary utilities
    "build_offset_to_vaddr",
    # Architecture detection
    "ArchInfo",
    "FeatureSupport",
    "detect_binary_arch_from_path",
    "get_feature_support",
    "get_raw_arch_info",
    # AI follow-up
    "AI_FOLLOWUP_VERSION",
    "request_ai_followup",
]
