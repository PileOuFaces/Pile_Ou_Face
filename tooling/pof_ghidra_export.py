# Pile ou Face Ghidra headless exporter.
# Usage: analyzeHeadless <project-dir> <project> -import <binary> \
#   -postScript pof_ghidra_export.py <output.json> <original-binary>

from ghidra.program.model.data import Array, Enum, FunctionDefinition, Pointer, Structure, TypeDef, Union
from ghidra.program.model.listing import CodeUnit
import hashlib
import json


def sha256_file(path):
    digest = hashlib.sha256()
    stream = open(path, "rb")
    try:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        stream.close()
    return digest.hexdigest()


def addr(value):
    return "0x%x" % value.getOffset()


def field_type(data_type):
    pointer_level = 0
    dimensions = []
    while isinstance(data_type, Pointer):
        pointer_level += 1
        data_type = data_type.getDataType()
    while isinstance(data_type, Array):
        dimensions.append(int(data_type.getNumElements()))
        data_type = data_type.getDataType()
    kind = "primitive"
    if isinstance(data_type, Structure):
        kind = "struct"
    elif isinstance(data_type, Union):
        kind = "union"
    elif isinstance(data_type, Enum):
        kind = "enum"
    return {
        "type": str(data_type.getName()),
        "type_kind": "pointer" if pointer_level else kind,
        "pointer_level": pointer_level,
        "array_len": dimensions[0] if dimensions else None,
        "array_dims": dimensions or None,
        "display_type": str(data_type.getDisplayName()),
    }


def export_type(data_type):
    name = str(data_type.getName())
    if isinstance(data_type, Enum):
        return {"name": name, "kind": "enum", "values": [
            {"name": str(member), "value": int(data_type.getValue(member))}
            for member in data_type.getNames()
        ]}
    if isinstance(data_type, (Structure, Union)):
        fields = []
        for index, component in enumerate(data_type.getComponents()):
            item = field_type(component.getDataType())
            item["name"] = str(component.getFieldName() or ("field_%d" % index))
            fields.append(item)
        return {"name": name, "kind": "union" if isinstance(data_type, Union) else "struct", "fields": fields}
    if isinstance(data_type, TypeDef):
        item = field_type(data_type.getBaseDataType())
        item["name"] = "target"
        return {"name": name, "kind": "typedef", "fields": [item]}
    if isinstance(data_type, FunctionDefinition):
        fields = []
        result = field_type(data_type.getReturnType())
        result["name"] = "return"
        fields.append(result)
        for index, argument in enumerate(data_type.getArguments()):
            item = field_type(argument.getDataType())
            item["name"] = str(argument.getName() or ("arg_%d" % index))
            fields.append(item)
        return {"name": name, "kind": "function", "fields": fields}
    return None


arguments = getScriptArgs()
if len(arguments) != 2:
    raise ValueError("Expected arguments: <output.json> <original-binary>")
output_path, binary_path = arguments
listing = currentProgram.getListing()
functions = []
iterator = listing.getFunctions(True)
while iterator.hasNext():
    function = iterator.next()
    entry = function.getEntryPoint()
    prototype_fields = []
    result = field_type(function.getReturnType())
    result["name"] = "return"
    prototype_fields.append(result)
    for index, parameter in enumerate(function.getParameters()):
        item = field_type(parameter.getDataType())
        item["name"] = str(parameter.getName() or ("arg_%d" % index))
        prototype_fields.append(item)
    functions.append({
        "addr": addr(entry),
        "name": str(function.getName()),
        "comment": function.getComment(),
        "prototype": {"fields": prototype_fields},
    })
comments = []
code_units = listing.getCodeUnits(True)
while code_units.hasNext():
    unit = code_units.next()
    for comment_type, label in (
        (CodeUnit.PLATE_COMMENT, "plate"),
        (CodeUnit.PRE_COMMENT, "pre"),
        (CodeUnit.POST_COMMENT, "post"),
        (CodeUnit.EOL_COMMENT, "eol"),
        (CodeUnit.REPEATABLE_COMMENT, "repeatable"),
    ):
        text = unit.getComment(comment_type)
        if text:
            comments.append({"addr": addr(unit.getAddress()), "type": label, "text": str(text)})
types = []
data_types = currentProgram.getDataTypeManager().getAllDataTypes()
while data_types.hasNext():
    try:
        exported = export_type(data_types.next())
        if exported:
            types.append(exported)
    except Exception as exc:
        printerr("Skipped Ghidra type: %s" % exc)
bookmarks = []
try:
    bookmark_iterator = currentProgram.getBookmarkManager().getBookmarksIterator()
    while bookmark_iterator.hasNext():
        bookmark = bookmark_iterator.next()
        bookmarks.append({
            "addr": addr(bookmark.getAddress()),
            "label": str(bookmark.getComment() or bookmark.getCategory() or bookmark.getTypeString()),
        })
except Exception as exc:
    printerr("Skipped Ghidra bookmarks: %s" % exc)
document = {
    "format": "pile-ou-face.canonical-import/v1",
    "source": {"tool": "ghidra", "program": str(currentProgram.getName())},
    "binary_sha256": sha256_file(binary_path),
    "functions": functions,
    "comments": comments,
    "types": types,
    "bookmarks": bookmarks,
}
stream = open(output_path, "w")
try:
    json.dump(document, stream, indent=2)
finally:
    stream.close()
println("Pile ou Face export written to %s" % output_path)
