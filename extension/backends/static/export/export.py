# SPDX-License-Identifier: AGPL-3.0-only
"""Export avancé des résultats d'analyse statique.

Supporte les formats : CSV (symboles, strings), JSON (xrefs IDA-like), DOT (CFG Graphviz).

Usage:
    from backends.static.export.export import (
        export_symbols_csv, export_strings_csv,
        export_xrefs_json, export_cfg_dot,
    )
    export_symbols_csv(symbols, "symbols.csv")
    export_cfg_dot(cfg, "cfg.dot")
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import TextIO

# ---------------------------------------------------------------------------
# CSV exports
# ---------------------------------------------------------------------------


def export_symbols_csv(symbols: list[dict], output_path: str) -> int:
    """Exporte les symboles au format CSV.

    Args:
        symbols: [{name, addr, type}, ...]
        output_path: Chemin de sortie

    Returns:
        Nombre de symboles exportés.
    """
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["addr", "name", "type"])
        writer.writeheader()
        for sym in symbols:
            writer.writerow(
                {
                    "addr": sym.get("addr", ""),
                    "name": sym.get("name", ""),
                    "type": sym.get("type", ""),
                }
            )
    return len(symbols)


def export_strings_csv(strings: list[dict], output_path: str) -> int:
    """Exporte les strings au format CSV.

    Args:
        strings: [{addr, value, length}, ...]
        output_path: Chemin de sortie

    Returns:
        Nombre de strings exportées.
    """
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["addr", "length", "value"])
        writer.writeheader()
        for s in strings:
            writer.writerow(
                {
                    "addr": s.get("addr", ""),
                    "length": s.get("length", ""),
                    "value": s.get("value", ""),
                }
            )
    return len(strings)


# ---------------------------------------------------------------------------
# JSON export (xrefs, IDA-like)
# ---------------------------------------------------------------------------


def export_xrefs_json(xref_map: dict, output_path: str) -> int:
    """Exporte la carte des xrefs au format JSON IDA-like.

    Format de sortie :
    {
      "0x401000": [
        {"from_addr": "0x401234", "type": "call", "from_line": 42},
        ...
      ],
      ...
    }

    Args:
        xref_map: Dictionnaire {target_addr: [ref_dict, ...]} tel que produit par
                  backends.static.disasm.xrefs.build_xref_map()
        output_path: Chemin de sortie JSON

    Returns:
        Nombre d'adresses cibles dans la carte.
    """
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(xref_map, f, indent=2, ensure_ascii=False)
    return len(xref_map)


# ---------------------------------------------------------------------------
# DOT export (CFG → Graphviz)
# ---------------------------------------------------------------------------

_DOT_EDGE_STYLES: dict[str, str] = {
    "jmp": 'color="black"',
    "jcc": 'color="blue" style="dashed"',
    "fallthrough": 'color="gray" style="dotted"',
    "call": 'color="red"',
    "jumptable": 'color="purple" style="dashed"',
}


def _escape_dot(text: str) -> str:
    """Échappe les caractères spéciaux pour DOT label."""
    return (
        text.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("<", "\\<")
        .replace(">", "\\>")
    )


def _block_label(block: dict) -> str:
    """Génère le label DOT d'un bloc de base."""
    lines = block.get("lines", [])
    addr = block.get("addr", "?")
    if lines:
        instrs = "\\l".join(_escape_dot(ln.get("text", "")) for ln in lines[:12])
        if len(lines) > 12:
            instrs += f"\\l... (+{len(lines) - 12} more)"
        label = f"{addr}:\\l{instrs}\\l"
    else:
        label = addr
    return label


def export_cfg_dot(cfg: dict, output_path: str, graph_name: str = "CFG") -> int:
    """Exporte le CFG au format DOT (Graphviz).

    Args:
        cfg: {"blocks": [...], "edges": [...]} tel que retourné par build_cfg()
             ou build_cfg_for_function()
        output_path: Chemin de sortie .dot
        graph_name: Nom du graphe (titre)

    Returns:
        Nombre de blocs exportés.
    """
    blocks = cfg.get("blocks", [])
    edges = cfg.get("edges", [])

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        _write_dot(f, blocks, edges, graph_name)
    return len(blocks)


def _write_dot(
    f: TextIO, blocks: list[dict], edges: list[dict], graph_name: str
) -> None:
    node_ids: dict[str, str] = {}

    def _node_id(addr: str) -> str:
        if addr not in node_ids:
            node_ids[addr] = f"n{len(node_ids)}"
        return node_ids[addr]

    f.write(f'digraph "{_escape_dot(graph_name)}" {{\n')
    f.write('  graph [fontname="Courier" rankdir="TB"];\n')
    f.write('  node  [shape="box" fontname="Courier" fontsize="10"];\n')
    f.write('  edge  [fontname="Courier" fontsize="9"];\n\n')

    # Nodes
    for block in blocks:
        addr = block.get("addr", "?")
        nid = _node_id(addr)
        label = _block_label(block)
        is_call = block.get("is_call", False)
        color = '"#ffe0e0"' if is_call else '"#e8f4e8"'
        f.write(f'  {nid} [label="{label}" fillcolor={color} style="filled"];\n')

    f.write("\n")

    # Edges
    for edge in edges:
        src = _node_id(edge.get("from", ""))
        dst = _node_id(edge.get("to", ""))
        etype = edge.get("type", "jmp")
        style = _DOT_EDGE_STYLES.get(etype, 'color="black"')
        f.write(f'  {src} -> {dst} [{style} label="{etype}"];\n')

    f.write("}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    """Point d'entrée CLI : exporte les résultats d'analyse en CSV/JSON/DOT."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Export static analysis results (CSV/JSON/DOT)"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # symbols-csv
    p_sym = sub.add_parser("symbols-csv", help="Export symbols to CSV")
    p_sym.add_argument("--input", required=True, help="Symbols JSON path")
    p_sym.add_argument("--output", required=True, help="Output CSV path")

    # strings-csv
    p_str = sub.add_parser("strings-csv", help="Export strings to CSV")
    p_str.add_argument("--input", required=True, help="Strings JSON path")
    p_str.add_argument("--output", required=True, help="Output CSV path")

    # xrefs-json
    p_xref = sub.add_parser("xrefs-json", help="Export xref map to JSON")
    p_xref.add_argument("--input", required=True, help="Xref map JSON path")
    p_xref.add_argument("--output", required=True, help="Output JSON path")

    # cfg-dot
    p_dot = sub.add_parser("cfg-dot", help="Export CFG to Graphviz DOT")
    p_dot.add_argument("--input", required=True, help="CFG JSON path")
    p_dot.add_argument("--output", required=True, help="Output .dot path")
    p_dot.add_argument("--name", default="CFG", help="Graph name")

    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as f:
        data = json.load(f)

    if args.cmd == "symbols-csv":
        symbols = data.get("symbols", data) if isinstance(data, dict) else data
        n = export_symbols_csv(symbols, args.output)
        print(f"Exported {n} symbols to {args.output}")

    elif args.cmd == "strings-csv":
        strings = data.get("strings", data) if isinstance(data, dict) else data
        n = export_strings_csv(strings, args.output)
        print(f"Exported {n} strings to {args.output}")

    elif args.cmd == "xrefs-json":
        n = export_xrefs_json(data, args.output)
        print(f"Exported xrefs for {n} addresses to {args.output}")

    elif args.cmd == "cfg-dot":
        n = export_cfg_dot(data, args.output, graph_name=args.name)
        print(f"Exported CFG ({n} blocks) to {args.output}")

    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
