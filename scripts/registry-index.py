#!/usr/bin/env python3
"""Writes registry/index.json, what `rr add --list` prints: each
component's name, description, dependencies and questions, from its own
JSON. With --check it compares instead and exits 1 when the index is
stale.

    python3 scripts/registry-index.py
    python3 scripts/registry-index.py --check
"""

import json
import sys
from pathlib import Path

REGISTRY = Path(__file__).resolve().parent.parent / "registry"


def index():
    items = []
    for path in sorted(REGISTRY.glob("*.json")):
        if path.name == "index.json":
            continue
        item = json.loads(path.read_text(encoding="utf-8"))
        entry = {
            "name": item["name"],
            "description": item.get("description", ""),
            "dependencies": item.get("dependencies", []),
        }
        options = [
            {"name": o["name"], "default": o["default"],
             "choices": [c["value"] for c in o["choices"]]}
            for o in item.get("options", [])
        ]
        if options:
            entry["options"] = options
        items.append(entry)
    return json.dumps({"components": items}, indent=2, ensure_ascii=False) + "\n"


def main():
    text = index()
    target = REGISTRY / "index.json"
    if sys.argv[1:] == ["--check"]:
        if not target.is_file() or target.read_text(encoding="utf-8") != text:
            sys.exit("registry-index: registry/index.json is stale; run scripts/registry-index.py")
        print("registry-index: registry/index.json is current")
    elif not sys.argv[1:]:
        target.write_text(text, encoding="utf-8")
    else:
        sys.exit("usage: registry-index.py [--check]")


main()
