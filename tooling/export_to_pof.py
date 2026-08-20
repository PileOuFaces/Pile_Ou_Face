# SPDX-License-Identifier: AGPL-3.0-only
"""IDAPython exporter for Pile ou Face canonical metadata.

Run from IDA with File > Script file, then choose the destination JSON.
"""

import binascii
import json

import ida_kernwin
import ida_nalt
import idautils
import idc


FORMAT = "pile-ou-face.canonical-import/v1"


def _sha256():
    digest = ida_nalt.retrieve_input_file_sha256()
    if isinstance(digest, str):
        return digest.lower()
    return binascii.hexlify(bytes(digest)).decode("ascii")


def _function_comment(ea):
    comments = []
    for repeatable in (False, True):
        value = idc.get_func_cmt(ea, repeatable)
        if value and value not in comments:
            comments.append(value)
    return "\n".join(comments)


def _export_structs():
    definitions = []
    try:
        structures = idautils.Structs()
    except Exception:
        return definitions
    for _index, sid, name in structures:
        fields = []
        try:
            members = idautils.StructMembers(sid)
        except Exception:
            continue
        for offset, member_name, size in members:
            size = max(1, int(size or 1))
            fields.append(
                {
                    "name": str(member_name or "field_%x" % int(offset)),
                    "type": "uint8_t",
                    "type_kind": "primitive",
                    "pointer_level": 0,
                    "array_len": size if size > 1 else None,
                    "array_dims": [size] if size > 1 else None,
                    "display_type": "uint8_t[%d]" % size if size > 1 else "uint8_t",
                }
            )
        if fields:
            definitions.append({"name": str(name), "kind": "struct", "fields": fields})
    return definitions


def _export_enums():
    definitions = []
    enum_iter = getattr(idautils, "Enums", None)
    member_iter = getattr(idautils, "EnumMembers", None)
    if not callable(enum_iter) or not callable(member_iter):
        return definitions
    try:
        for enum_id in enum_iter():
            name = idc.get_enum_name(enum_id)
            values = [
                {"name": str(member_name), "value": int(value)}
                for value, member_name, _serial, _bitmask in member_iter(enum_id)
            ]
            if name and values:
                definitions.append(
                    {"name": str(name), "kind": "enum", "values": values}
                )
    except Exception:
        pass
    return definitions


def _export_locals(ea):
    try:
        import ida_hexrays

        if not ida_hexrays.init_hexrays_plugin():
            return []
        cfunc = ida_hexrays.decompile(ea)
        return [
            {
                "name": str(variable.name),
                "type": str(variable.type()),
                "is_stack": bool(variable.is_stk_var()),
            }
            for variable in cfunc.get_lvars()
            if variable.name
        ]
    except Exception:
        return []


def _export_bookmarks():
    get_position = getattr(idc, "GetMarkedPos", None)
    get_comment = getattr(idc, "GetMarkComment", None)
    if not callable(get_position) or not callable(get_comment):
        return []
    bookmarks = []
    for slot in range(1024):
        try:
            ea = get_position(slot)
        except Exception:
            break
        if ea in (None, idc.BADADDR):
            continue
        try:
            label = get_comment(slot)
        except Exception:
            label = ""
        bookmarks.append({"addr": hex(ea), "label": str(label or hex(ea))})
    return bookmarks


def build_document():
    function_addresses = set(idautils.Functions())
    functions = []
    for ea in sorted(function_addresses):
        functions.append(
            {
                "addr": hex(ea),
                "name": idc.get_func_name(ea),
                "comment": _function_comment(ea),
                "prototype": idc.get_type(ea),
                "locals": _export_locals(ea),
            }
        )
    comments = []
    for ea in idautils.Heads():
        if ea in function_addresses:
            continue
        regular = idc.get_cmt(ea, False)
        repeatable = idc.get_cmt(ea, True)
        values = [value for value in (regular, repeatable) if value]
        if values:
            comments.append(
                {
                    "addr": hex(ea),
                    "type": "repeatable" if repeatable and not regular else "regular",
                    "text": "\n".join(dict.fromkeys(values)),
                }
            )
    return {
        "format": FORMAT,
        "source": {"tool": "ida", "database": str(ida_nalt.get_root_filename())},
        "binary_sha256": _sha256(),
        "functions": functions,
        "comments": comments,
        "types": _export_structs() + _export_enums(),
        "bookmarks": _export_bookmarks(),
    }


destination = ida_kernwin.ask_file(True, "*.json", "Exporter vers Pile ou Face")
if destination:
    with open(destination, "w", encoding="utf-8") as stream:
        json.dump(build_document(), stream, indent=2, ensure_ascii=False)
    ida_kernwin.info("Export Pile ou Face écrit dans %s" % destination)
