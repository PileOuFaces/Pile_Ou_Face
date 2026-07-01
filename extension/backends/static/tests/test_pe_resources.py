# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends/static/binary/pe_resources.py — vise 100 % de couverture.

Organisation :
  - Fixtures binaires pures (pas de LIEF)
  - Tests unitaires de chaque fonction privée
  - Tests d'intégration de get_pe_resources (avec mocks LIEF + vraie ELF)
  - Tests CLI (subprocess)
"""
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, ROOT)

import backends.static.binary.pe_resources as _mod
from backends.static.binary.pe_resources import (
    _align4,
    _decode_resource,
    _decode_rt_bitmap_icon,
    _decode_rt_manifest,
    _decode_rt_string,
    _decode_rt_version,
    _hex_preview,
    _parse_string_file_info,
    _parse_string_table_entries,
    _read_utf16_key,
    get_pe_resources,
)
from backends.static.tests.fixtures.make_elf import make_minimal_elf

try:
    import lief as _lief

    _LIEF_AVAILABLE = True
except ImportError:
    _LIEF_AVAILABLE = False


# ── Helpers de construction de binaires RT_VERSION ──────────────────────────

def _utf16le(s: str) -> bytes:
    return s.encode("utf-16-le") + b"\x00\x00"


def _pad4(b: bytes) -> bytes:
    r = len(b) % 4
    return b + b"\x00" * ((4 - r) % 4)


def _make_string_entry(key: str, value: str) -> bytes:
    """Construit un bloc String VS_VERSION_INFO."""
    k = _utf16le(key)
    v = _utf16le(value)
    val_words = len(v) // 2
    body = struct.pack("<HHH", 0, val_words, 1) + k
    body = _pad4(body) + v
    body = _pad4(body)
    result = bytearray(body)
    struct.pack_into("<H", result, 0, len(result))
    return bytes(result)


def _make_string_table(lang: str, strings: dict) -> bytes:
    """Construit un bloc StringTable."""
    k = _utf16le(lang)
    children = b"".join(_make_string_entry(key, val) for key, val in strings.items())
    body = struct.pack("<HHH", 0, 0, 1) + k
    body = _pad4(body) + children
    body = _pad4(body)
    result = bytearray(body)
    struct.pack_into("<H", result, 0, len(result))
    return bytes(result)


def _make_string_file_info(lang: str, strings: dict) -> bytes:
    """Construit un bloc StringFileInfo complet."""
    k = _utf16le("StringFileInfo")
    child = _make_string_table(lang, strings)
    body = struct.pack("<HHH", 0, 0, 1) + k
    body = _pad4(body) + child
    body = _pad4(body)
    result = bytearray(body)
    struct.pack_into("<H", result, 0, len(result))
    return bytes(result)


def _make_fixed_file_info(file_ver=(1, 2, 3, 4), prod_ver=(5, 6, 7, 8)) -> bytes:
    """Construit un FixedFileInfo avec le magic LIEF attend (0xFEEF04BD)."""
    # dwSignature(4) + dwStrucVersion(4) + dwFileVersionMS(4) + dwFileVersionLS(4)
    # + dwProductVersionMS(4) + dwProductVersionLS(4) + ... (reste de la struct, 52 bytes total)
    fv_ms = (file_ver[0] << 16) | file_ver[1]
    fv_ls = (file_ver[2] << 16) | file_ver[3]
    pv_ms = (prod_ver[0] << 16) | prod_ver[1]
    pv_ls = (prod_ver[2] << 16) | prod_ver[3]
    return struct.pack(
        "<IIIIIIII",
        0xFEEF04BD,  # dwSignature
        0x00010000,  # dwStrucVersion
        fv_ms,
        fv_ls,
        pv_ms,
        pv_ls,
        0,
        0,
    ) + bytes(52 - 32)  # rembourrage pour atteindre 52 bytes


def _make_version_binary(
    file_ver=(1, 2, 3, 4),
    prod_ver=(5, 6, 7, 8),
    strings: dict | None = None,
) -> bytes:
    """Construit un binaire RT_VERSION complet avec FixedFileInfo + StringFileInfo."""
    ffi = _make_fixed_file_info(file_ver, prod_ver)
    sfi = _make_string_file_info("040904b0", strings or {}) if strings is not None else b""

    root_key = _utf16le("VS_VERSION_INFO")
    # Header (6) + key
    header_and_key = struct.pack("<HHH", 0, len(ffi), 0) + root_key
    header_and_key = _pad4(header_and_key)
    body = header_and_key + ffi
    body = _pad4(body) + sfi
    body = _pad4(body)
    result = bytearray(body)
    struct.pack_into("<H", result, 0, len(result))
    return bytes(result)


# ── Helper LIEF mock ─────────────────────────────────────────────────────────

def _make_lief_pe_mock(resources_spec=None, resources_obj=None):
    """
    Retourne un mock lief.PE.Binary.
    resources_spec : liste de (type_id, name_or_id, lang_id, content_bytes)
    resources_obj  : objet root custom (prioritaire sur resources_spec)
    """
    binary = MagicMock(spec=_lief.PE.Binary) if _LIEF_AVAILABLE else MagicMock()
    if resources_obj is False:
        binary.resources = None
        return binary

    if resources_obj is not None:
        binary.resources = resources_obj
        return binary

    if resources_spec is None:
        binary.resources = None
        return binary

    root = MagicMock()
    type_map: dict = {}
    for type_id, name_or_id, lang_id, content in resources_spec:
        if type_id not in type_map:
            tn = MagicMock()
            tn.id = type_id
            tn.childs = []
            type_map[type_id] = tn

        nn = MagicMock()
        if isinstance(name_or_id, str):
            nn.has_name = True
            nn.name = name_or_id
        else:
            nn.has_name = False
            nn.id = name_or_id

        ln = MagicMock()
        ln.id = lang_id
        ln.content = list(content)
        nn.childs = [ln]
        type_map[type_id].childs.append(nn)

    root.childs = list(type_map.values())
    binary.resources = root
    return binary


def run_cli(binary_path: str) -> dict:
    r = subprocess.run(
        [sys.executable, "backends/static/binary/pe_resources.py", "--binary", binary_path],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    return json.loads(r.stdout)


# ────────────────────────────────────────────────────────────────────────────
# Tests _align4
# ────────────────────────────────────────────────────────────────────────────

class TestAlign4(unittest.TestCase):
    def test_zero(self):
        self.assertEqual(_align4(0), 0)

    def test_already_aligned(self):
        self.assertEqual(_align4(4), 4)
        self.assertEqual(_align4(8), 8)

    def test_needs_padding(self):
        self.assertEqual(_align4(1), 4)
        self.assertEqual(_align4(2), 4)
        self.assertEqual(_align4(3), 4)
        self.assertEqual(_align4(5), 8)


# ────────────────────────────────────────────────────────────────────────────
# Tests _read_utf16_key
# ────────────────────────────────────────────────────────────────────────────

class TestReadUtf16Key(unittest.TestCase):
    def test_normal_key(self):
        data = "Hello".encode("utf-16-le") + b"\x00\x00" + b"x" * 10
        key, after = _read_utf16_key(data, 0, len(data))
        self.assertEqual(key, "Hello")
        self.assertEqual(after, 12)  # 10 bytes + 2 null

    def test_empty_key_immediate_null(self):
        data = b"\x00\x00" + b"rest"
        key, after = _read_utf16_key(data, 0, len(data))
        self.assertEqual(key, "")
        self.assertEqual(after, 2)

    def test_key_at_limit(self):
        """Si la limite est atteinte sans null terminateur, on retourne ce qu'on a."""
        data = "AB".encode("utf-16-le")  # 4 bytes, pas de null
        key, after = _read_utf16_key(data, 0, len(data))
        self.assertEqual(key, "AB")
        self.assertEqual(after, 6)  # pos=4 (at limit), +2


# ────────────────────────────────────────────────────────────────────────────
# Tests _hex_preview
# ────────────────────────────────────────────────────────────────────────────

class TestHexPreview(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(_hex_preview(b""), "")

    def test_short_no_truncation(self):
        self.assertEqual(_hex_preview(b"\x00\xff\x0a"), "00 ff 0a")

    def test_truncates_at_max(self):
        data = bytes(range(30))
        result = _hex_preview(data, max_bytes=3)
        self.assertEqual(result, "00 01 02")


# ────────────────────────────────────────────────────────────────────────────
# Tests _decode_rt_string
# ────────────────────────────────────────────────────────────────────────────

class TestDecodeRtString(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(_decode_rt_string(b""), {"strings": []})

    def test_zero_length_entry_skipped(self):
        data = struct.pack("<H", 0)  # length=0, skipped
        self.assertEqual(_decode_rt_string(data), {"strings": []})

    def test_valid_string(self):
        text = "Hello"
        length = len(text)
        data = struct.pack("<H", length) + text.encode("utf-16-le")
        result = _decode_rt_string(data)
        self.assertIn("Hello", result["strings"])

    def test_incomplete_data_skipped(self):
        # length claims 10 chars but data only has 2 chars
        data = struct.pack("<H", 10) + "AB".encode("utf-16-le")
        result = _decode_rt_string(data)
        self.assertEqual(result["strings"], [])

    def test_single_byte_at_end(self):
        """Un seul octet restant (pas de paire complète) — on s'arrête proprement."""
        data = b"\x41"  # 1 byte, cannot form a length word
        self.assertEqual(_decode_rt_string(data), {"strings": []})


# ────────────────────────────────────────────────────────────────────────────
# Tests _decode_rt_manifest
# ────────────────────────────────────────────────────────────────────────────

class TestDecodeRtManifest(unittest.TestCase):
    def test_short_xml(self):
        xml = "<manifest/>"
        result = _decode_rt_manifest(xml.encode("utf-8"))
        self.assertEqual(result["xml"], xml)

    def test_truncated_at_2000(self):
        xml = "A" * 3000
        result = _decode_rt_manifest(xml.encode("utf-8"))
        self.assertEqual(len(result["xml"]), 2000)


# ────────────────────────────────────────────────────────────────────────────
# Tests _parse_string_file_info
# ────────────────────────────────────────────────────────────────────────────

class TestParseStringTableEntries(unittest.TestCase):
    def test_w_len_too_small_breaks(self):
        """w_len < 6 → break immédiat, retour {}."""
        data = struct.pack("<H", 3) + b"\x00" * 20
        result = _parse_string_table_entries(data, 0, len(data))
        self.assertEqual(result, {})

    def test_w_len_zero_breaks(self):
        data = struct.pack("<H", 0) + b"\x00" * 20
        result = _parse_string_table_entries(data, 0, len(data))
        self.assertEqual(result, {})


class TestParseStringFileInfo(unittest.TestCase):
    def test_no_string_file_info_needle(self):
        self.assertEqual(_parse_string_file_info(b"garbage data"), {})

    def test_needle_too_early_no_header_space(self):
        # "StringFileInfo" in UTF-16LE at offset 0 → sfi_start = -6 → {}
        data = "StringFileInfo".encode("utf-16-le") + b"\x00\x00"
        self.assertEqual(_parse_string_file_info(data), {})

    def test_single_string_entry(self):
        data = _make_string_file_info("040904b0", {"ProductName": "Pile ou Face"})
        result = _parse_string_file_info(data)
        self.assertEqual(result.get("ProductName"), "Pile ou Face")

    def test_multiple_string_entries(self):
        data = _make_string_file_info("040904b0", {
            "ProductName": "Pile ou Face",
            "CompanyName": "PileOuFaces",
            "OriginalFilename": "test.exe",
        })
        result = _parse_string_file_info(data)
        self.assertEqual(result["ProductName"], "Pile ou Face")
        self.assertEqual(result["CompanyName"], "PileOuFaces")
        self.assertEqual(result["OriginalFilename"], "test.exe")

    def test_empty_strings_dict(self):
        data = _make_string_file_info("040904b0", {})
        result = _parse_string_file_info(data)
        self.assertIsInstance(result, dict)

    def test_zero_val_length_entry_skipped(self):
        """Un String entry avec wValueLength=0 ne doit pas planter."""
        # Construit manuellement une entrée avec wValueLength=0
        k = _utf16le("EmptyKey")
        body = struct.pack("<HHH", 0, 0, 1) + k
        body = _pad4(body)
        entry = bytearray(body)
        struct.pack_into("<H", entry, 0, len(entry))
        # Enveloppe dans StringTable + StringFileInfo
        lang_k = _utf16le("040904b0")
        st_body = struct.pack("<HHH", 0, 0, 1) + lang_k
        st_body = _pad4(st_body) + bytes(entry)
        st_body = _pad4(st_body)
        st = bytearray(st_body)
        struct.pack_into("<H", st, 0, len(st))
        sfi_k = _utf16le("StringFileInfo")
        sfi_body = struct.pack("<HHH", 0, 0, 1) + sfi_k
        sfi_body = _pad4(sfi_body) + bytes(st)
        sfi_body = _pad4(sfi_body)
        sfi = bytearray(sfi_body)
        struct.pack_into("<H", sfi, 0, len(sfi))
        result = _parse_string_file_info(bytes(sfi))
        self.assertIsInstance(result, dict)

    def test_string_table_len_too_small_breaks(self):
        """st_len < 6 dans le loop StringTable → break."""
        sfi_k = _utf16le("StringFileInfo")
        # StringTable avec w_len = 3 (invalide)
        st_invalid = struct.pack("<H", 3) + b"\x00" * 30
        sfi_body = struct.pack("<HHH", 0, 0, 1) + sfi_k
        sfi_body = _pad4(sfi_body) + st_invalid
        sfi_body = _pad4(sfi_body)
        sfi = bytearray(sfi_body)
        struct.pack_into("<H", sfi, 0, len(sfi))
        result = _parse_string_file_info(bytes(sfi))
        self.assertEqual(result, {})


# ────────────────────────────────────────────────────────────────────────────
# Tests _decode_rt_version
# ────────────────────────────────────────────────────────────────────────────

class TestDecodeRtVersion(unittest.TestCase):
    def test_no_magic_no_strings_returns_raw(self):
        self.assertEqual(_decode_rt_version(b"no magic here"), {"raw": True})

    def test_magic_found_extracts_versions(self):
        data = _make_version_binary(file_ver=(1, 2, 3, 4), prod_ver=(5, 6, 7, 8))
        result = _decode_rt_version(data)
        self.assertEqual(result["file_version"], "1.2.3.4")
        self.assertEqual(result["product_version"], "5.6.7.8")

    def test_magic_truncated_returns_zero_versions(self):
        # Magic présent mais données trop courtes : les slices Python ne lèvent pas d'exception,
        # int.from_bytes(b"", "little") == 0 → versions à 0.0.0.0
        data = b"\xbd\x04\xef\xfe" + b"\x00" * 4
        result = _decode_rt_version(data)
        self.assertEqual(result["file_version"], "0.0.0.0")
        self.assertEqual(result["product_version"], "0.0.0.0")

    def test_string_file_info_extracted(self):
        data = _make_version_binary(
            file_ver=(2, 0, 0, 0),
            prod_ver=(2, 0, 0, 0),
            strings={"ProductName": "Pile ou Face", "OriginalFilename": "app.exe"},
        )
        result = _decode_rt_version(data)
        self.assertEqual(result["file_version"], "2.0.0.0")
        self.assertEqual(result["ProductName"], "Pile ou Face")
        self.assertEqual(result["OriginalFilename"], "app.exe")

    def test_no_magic_but_strings(self):
        """StringFileInfo sans FixedFileInfo — doit quand même extraire les strings."""
        data = _make_string_file_info("040904b0", {"CompanyName": "ACME"})
        result = _decode_rt_version(data)
        self.assertEqual(result.get("CompanyName"), "ACME")
        self.assertNotIn("file_version", result)

    def test_empty_data_returns_raw(self):
        self.assertEqual(_decode_rt_version(b""), {"raw": True})


# ────────────────────────────────────────────────────────────────────────────
# Tests _decode_rt_bitmap_icon
# ────────────────────────────────────────────────────────────────────────────

class TestDecodeRtBitmapIcon(unittest.TestCase):
    def _bmp_header(self, w=32, h=32, bpp=24) -> bytes:
        """BITMAPINFOHEADER minimal (40 bytes)."""
        return struct.pack("<IiiHH", 40, w, h, 1, bpp) + bytes(24)

    def test_too_short_returns_empty(self):
        self.assertEqual(_decode_rt_bitmap_icon(b"\x00" * 10, "RT_BITMAP"), {})

    def test_bitmap_height_absolute(self):
        data = self._bmp_header(w=64, h=-48, bpp=32)
        result = _decode_rt_bitmap_icon(data, "RT_BITMAP")
        self.assertEqual(result["width"], 64)
        self.assertEqual(result["height"], 48)
        self.assertEqual(result["bpp"], 32)

    def test_icon_height_halved(self):
        data = self._bmp_header(w=32, h=64, bpp=32)
        result = _decode_rt_bitmap_icon(data, "RT_ICON")
        self.assertEqual(result["height"], 32)  # 64 // 2

    def test_negative_icon_height(self):
        data = self._bmp_header(w=16, h=-64, bpp=8)
        result = _decode_rt_bitmap_icon(data, "RT_ICON")
        self.assertEqual(result["height"], 32)  # abs(-64) // 2


# ────────────────────────────────────────────────────────────────────────────
# Tests _decode_resource
# ────────────────────────────────────────────────────────────────────────────

class TestDecodeResource(unittest.TestCase):
    def test_rt_string(self):
        r = _decode_resource("RT_STRING", b"")
        self.assertIn("strings", r)

    def test_rt_manifest(self):
        r = _decode_resource("RT_MANIFEST", b"<x/>")
        self.assertEqual(r["xml"], "<x/>")

    def test_rt_version(self):
        r = _decode_resource("RT_VERSION", b"no magic")
        self.assertEqual(r, {"raw": True})

    def test_rt_bitmap(self):
        r = _decode_resource("RT_BITMAP", b"\x00" * 16)
        self.assertIsInstance(r, dict)

    def test_rt_icon(self):
        r = _decode_resource("RT_ICON", b"\x00" * 16)
        self.assertIsInstance(r, dict)

    def test_rt_rcdata(self):
        r = _decode_resource("RT_RCDATA", b"\xde\xad\xbe\xef")
        self.assertIn("hex", r)
        self.assertEqual(r["size"], 4)

    def test_unknown_type_returns_none(self):
        self.assertIsNone(_decode_resource("RT_CURSOR", b"\x00"))
        self.assertIsNone(_decode_resource("RT_UNKNOWN_999", b"\x00"))


# ────────────────────────────────────────────────────────────────────────────
# Tests get_pe_resources
# ────────────────────────────────────────────────────────────────────────────

class TestGetPeResources(unittest.TestCase):
    def test_lief_not_available(self):
        with patch.object(_mod, "_LIEF_AVAILABLE", False):
            result = get_pe_resources("/any/path.exe")
        self.assertIsNotNone(result["error"])
        self.assertFalse(result.get("applicable", True))

    def test_missing_file(self):
        result = get_pe_resources("/nonexistent/binary.exe")
        self.assertIsNotNone(result["error"])
        self.assertIn("resources", result)

    @unittest.skipUnless(_LIEF_AVAILABLE, "lief non disponible")
    def test_lief_parse_returns_none(self):
        with patch.object(_mod.lief, "parse", return_value=None):
            result = get_pe_resources("/fake/path.exe")
        # get_pe_resources vérifie os.path.isfile avant lief.parse, on doit patcher ça aussi
        # → utiliser un vrai fichier temporaire
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"not a pe")
            tmp = f.name
        try:
            with patch.object(_mod.lief, "parse", return_value=None):
                result = get_pe_resources(tmp)
            self.assertIsNotNone(result["error"])
        finally:
            os.unlink(tmp)

    @unittest.skipUnless(_LIEF_AVAILABLE, "lief non disponible")
    def test_non_pe_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            elf = os.path.join(tmp, "test.elf")
            make_minimal_elf(elf)
            result = get_pe_resources(elf)
        self.assertIsNone(result.get("error"))
        self.assertFalse(result.get("applicable"))
        self.assertIn("PE", result.get("message", ""))

    @unittest.skipUnless(_LIEF_AVAILABLE, "lief non disponible")
    def test_pe_no_resources(self):
        mock_binary = _make_lief_pe_mock(resources_obj=False)
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"fake")
            tmp = f.name
        try:
            with patch.object(_mod.lief, "parse", return_value=mock_binary):
                result = get_pe_resources(tmp)
        finally:
            os.unlink(tmp)
        self.assertIsNone(result["error"])
        self.assertEqual(result["resources"], [])
        self.assertTrue(result.get("applicable"))

    @unittest.skipUnless(_LIEF_AVAILABLE, "lief non disponible")
    def test_pe_with_known_type_resource(self):
        """RT_MANIFEST (type_id=24) avec un nom numérique."""
        content = b"<manifest/>"
        mock_binary = _make_lief_pe_mock(resources_spec=[(24, 1, 1033, content)])
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"fake")
            tmp = f.name
        try:
            with patch.object(_mod.lief, "parse", return_value=mock_binary):
                result = get_pe_resources(tmp)
        finally:
            os.unlink(tmp)
        self.assertIsNone(result["error"])
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["resources"][0]["type"], "RT_MANIFEST")
        self.assertEqual(result["resources"][0]["decoded"]["xml"], "<manifest/>")

    @unittest.skipUnless(_LIEF_AVAILABLE, "lief non disponible")
    def test_pe_with_named_resource(self):
        """Ressource avec un nom texte (has_name=True)."""
        content = b"\xde\xad\xbe\xef"
        mock_binary = _make_lief_pe_mock(resources_spec=[(10, "MY_DATA", 1033, content)])
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"fake")
            tmp = f.name
        try:
            with patch.object(_mod.lief, "parse", return_value=mock_binary):
                result = get_pe_resources(tmp)
        finally:
            os.unlink(tmp)
        self.assertEqual(result["resources"][0]["id"], "MY_DATA")

    @unittest.skipUnless(_LIEF_AVAILABLE, "lief non disponible")
    def test_pe_with_unknown_type_id(self):
        """Type ID inconnu → nom généré 'RT_<id>'."""
        content = b"\x00"
        mock_binary = _make_lief_pe_mock(resources_spec=[(999, 1, 0, content)])
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"fake")
            tmp = f.name
        try:
            with patch.object(_mod.lief, "parse", return_value=mock_binary):
                result = get_pe_resources(tmp)
        finally:
            os.unlink(tmp)
        self.assertEqual(result["resources"][0]["type"], "RT_999")

    @unittest.skipUnless(_LIEF_AVAILABLE, "lief non disponible")
    def test_pe_lang_node_exception_skipped(self):
        """Une exception dans la lecture du contenu d'un lang_node est silencieuse."""
        from unittest.mock import PropertyMock
        mock_binary = MagicMock(spec=_lief.PE.Binary)
        root = MagicMock()
        type_node = MagicMock()
        type_node.id = 24
        name_node = MagicMock()
        name_node.has_name = False
        name_node.id = 1
        lang_node = MagicMock()
        lang_node.id = 0
        type(lang_node).content = PropertyMock(side_effect=RuntimeError("boom"))
        name_node.childs = [lang_node]
        type_node.childs = [name_node]
        root.childs = [type_node]
        mock_binary.resources = root
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"fake")
            tmp = f.name
        try:
            with patch.object(_mod.lief, "parse", return_value=mock_binary):
                result = get_pe_resources(tmp)
        finally:
            os.unlink(tmp)
        self.assertIn("resources", result)

    @unittest.skipUnless(_LIEF_AVAILABLE, "lief non disponible")
    def test_pe_root_childs_iteration_raises_outer_except(self):
        """Exception sur root.childs → branche except externe → error dans résultat."""
        from unittest.mock import PropertyMock
        mock_binary = MagicMock(spec=_lief.PE.Binary)
        root = MagicMock()
        type(root).childs = PropertyMock(side_effect=RuntimeError("root fail"))
        mock_binary.resources = root
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"fake")
            tmp = f.name
        try:
            with patch.object(_mod.lief, "parse", return_value=mock_binary):
                result = get_pe_resources(tmp)
        finally:
            os.unlink(tmp)
        self.assertIsNotNone(result.get("error"))


# ────────────────────────────────────────────────────────────────────────────
# Test main()
# ────────────────────────────────────────────────────────────────────────────

class TestMain(unittest.TestCase):
    def test_main_returns_zero_and_outputs_json(self):
        """main() imprime du JSON valide sur stdout et retourne 0."""
        import io
        from contextlib import redirect_stdout
        from backends.static.binary.pe_resources import main

        buf = io.StringIO()
        with patch("sys.argv", ["pe_resources.py", "--binary", "/nonexistent.exe"]):
            with redirect_stdout(buf):
                ret = main()
        self.assertEqual(ret, 0)
        output = json.loads(buf.getvalue())
        self.assertIn("error", output)

    def test_main_block_via_runpy(self):
        """Couvre if __name__ == '__main__': sys.exit(main())."""
        import io
        import runpy
        from contextlib import redirect_stdout

        buf = io.StringIO()
        script = os.path.join(ROOT, "backends/static/binary/pe_resources.py")
        with patch("sys.argv", ["pe_resources.py", "--binary", "/nonexistent.exe"]):
            with patch("sys.exit") as mock_exit:
                with redirect_stdout(buf):
                    runpy.run_path(script, run_name="__main__")
        mock_exit.assert_called_once_with(0)


# ────────────────────────────────────────────────────────────────────────────
# Test branche ImportError (lief indisponible au chargement du module)
# ────────────────────────────────────────────────────────────────────────────

class TestLiefImportError(unittest.TestCase):
    def test_module_sets_lief_none_when_import_fails(self):
        """Couvre except ImportError: lief = None; _LIEF_AVAILABLE = False."""
        import builtins
        import importlib.util

        real_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "lief":
                raise ImportError("mocked unavailable")
            return real_import(name, *args, **kwargs)

        # Vider le cache du module cible
        mod_key = "backends.static.binary.pe_resources"
        saved_mod = sys.modules.pop(mod_key, None)
        saved_lief = sys.modules.pop("lief", None)
        try:
            with patch("builtins.__import__", side_effect=mock_import):
                spec = importlib.util.spec_from_file_location(
                    "_pe_resources_no_lief",
                    os.path.join(ROOT, "backends/static/binary/pe_resources.py"),
                )
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
            self.assertFalse(mod._LIEF_AVAILABLE)
            self.assertIsNone(mod.lief)
        finally:
            if saved_mod is not None:
                sys.modules[mod_key] = saved_mod
            if saved_lief is not None:
                sys.modules["lief"] = saved_lief


# ────────────────────────────────────────────────────────────────────────────
# Tests CLI (subprocess)
# ────────────────────────────────────────────────────────────────────────────

class TestCli(unittest.TestCase):
    def test_missing_binary_via_cli(self):
        result = run_cli("/nonexistent/binary.exe")
        self.assertIn("error", result)
        self.assertIsNotNone(result["error"])

    def test_output_is_valid_json(self):
        result = run_cli("/nonexistent/binary.exe")
        self.assertIsInstance(result, dict)

    def test_schema_always_present(self):
        result = run_cli("/nonexistent/binary.exe")
        for key in ("error", "resources", "count"):
            self.assertIn(key, result)

    @unittest.skipUnless(_LIEF_AVAILABLE, "lief non disponible")
    def test_elf_via_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            elf = os.path.join(tmp, "test.elf")
            make_minimal_elf(elf)
            result = run_cli(elf)
        self.assertFalse(result.get("applicable"))


if __name__ == "__main__":
    unittest.main()
