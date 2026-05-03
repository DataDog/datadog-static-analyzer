#!/usr/bin/env python3
"""
Normalize a SARIF file to a stable fingerprint (set of finding tuples + sha256).

Usage:
    fingerprint.py <sarif_path>           -> prints {sha256, count}
    fingerprint.py --diff a.sarif b.sarif -> prints diff stats
"""
import hashlib
import json
import sys
from typing import Iterable


def iter_findings(sarif_path: str) -> Iterable[tuple]:
    """Yield (rule_id, file, start_line, start_col, end_line, end_col, message) tuples."""
    with open(sarif_path) as f:
        data = json.load(f)
    for run in data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            msg = result.get("message", {}).get("text", "")
            for loc in result.get("locations", []) or []:
                phys = loc.get("physicalLocation", {}) or {}
                art = phys.get("artifactLocation", {}) or {}
                region = phys.get("region", {}) or {}
                yield (
                    rule_id,
                    art.get("uri", ""),
                    region.get("startLine"),
                    region.get("startColumn"),
                    region.get("endLine"),
                    region.get("endColumn"),
                    msg,
                )


def fingerprint(sarif_path: str) -> tuple[str, int]:
    findings = sorted(set(iter_findings(sarif_path)))
    h = hashlib.sha256()
    for f in findings:
        h.update(repr(f).encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest(), len(findings)


def diff(a_path: str, b_path: str) -> dict:
    a = set(iter_findings(a_path))
    b = set(iter_findings(b_path))
    return {
        "a_only_count": len(a - b),
        "b_only_count": len(b - a),
        "common_count": len(a & b),
        "a_total": len(a),
        "b_total": len(b),
        "match": a == b,
    }


def main():
    args = sys.argv[1:]
    if not args:
        print("usage: fingerprint.py <sarif> | fingerprint.py --diff a b", file=sys.stderr)
        sys.exit(2)
    if args[0] == "--diff":
        d = diff(args[1], args[2])
        print(json.dumps(d))
        sys.exit(0 if d["match"] else 1)
    sha, count = fingerprint(args[0])
    print(json.dumps({"sha256": sha, "count": count}))


if __name__ == "__main__":
    main()
