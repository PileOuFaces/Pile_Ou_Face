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
"""

from backends.shared.log import configure_logging, get_logger
from backends.shared.utils import build_offset_to_vaddr
from backends.static.binary.arch import (
    ArchInfo,
    FeatureSupport,
    detect_binary_arch_from_path,
    get_feature_support,
    get_raw_arch_info,
)

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
]
