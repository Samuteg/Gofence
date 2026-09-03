#!/usr/bin/env python3
"""Converte `go test -json` em TAP com títulos `@spec:AC-xxx`.

Uso (via onpspec.config.json):
    go test -json ./... | python3 .spec/go-tap.py

As tags vêm dos comentários `// @spec:AC-xxx` acima de cada `func Test...`
nos arquivos `*_test.go`. Testes sem tag saem no TAP sem tag (são
ignorados pelo motor, sem quebrar nada).
"""

import json
import re
import sys
from pathlib import Path

RE_TAG = re.compile(r"@spec:(AC-\d{3,})")
RE_FUNC = re.compile(r"^func\s+(Test\w+)\s*\(")


def collect_tags(root: Path) -> dict:
    """Mapeia nome do teste -> lista de AC ids (ex.: TestFoo -> [AC-001])."""
    mapping: dict = {}
    for path in sorted(root.glob("**/*_test.go")):
        pending: list = []
        for line in path.read_text().splitlines():
            s = line.strip()
            for tag in RE_TAG.findall(s):
                if tag not in pending:
                    pending.append(tag)
            m = RE_FUNC.match(s)
            if m:
                if pending:
                    mapping.setdefault(m.group(1), []).extend(
                        t for t in pending if t not in mapping.get(m.group(1), [])
                    )
                pending = []
    return mapping


def main() -> int:
    root = Path.cwd()
    tags = collect_tags(root)

    verdicts: dict = {}  # (pkg, test) -> pass|fail|skip
    pkg_failed: dict = {}  # pkg -> bool (falha sem testes, ex.: build quebrou)

    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            ev = json.loads(raw)
        except json.JSONDecodeError:
            continue
        action = ev.get("Action")
        pkg = ev.get("Package", "")
        test = ev.get("Test", "")
        if test and "/" in test:
            test = test.split("/")[0]  # subteste herda o pai
        if test and action in ("pass", "fail", "skip"):
            verdicts[(pkg, test)] = action
        elif not test and action == "fail":
            pkg_failed[pkg] = True

    rows = []
    failed = False
    for (pkg, test) in sorted(verdicts):
        acs = tags.get(test, [])
        prefix = " ".join(f"@spec:{a}" for a in acs)
        title = f"{prefix} {test} ({pkg})".strip()
        status = verdicts[(pkg, test)]
        if status == "pass":
            rows.append(f"ok - {title}")
        elif status == "skip":
            rows.append(f"ok - {title} # SKIP")
            failed = True
        else:
            rows.append(f"not ok - {title}")
            failed = True

    tested_pkgs = {p for (p, _) in verdicts}
    for pkg in sorted(pkg_failed):
        if pkg not in tested_pkgs:
            rows.append(f"not ok - {pkg} (suite failed, no tests ran)")
            failed = True

    lines = [f"{r.split(' - ', 1)[0]} {i} - {r.split(' - ', 1)[1]}" for i, r in enumerate(rows, 1)]

    sys.stdout.write("\n".join(lines) + ("\n" if lines else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
