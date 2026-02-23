#!/usr/bin/env python3
"""Batch runner for paper figures.

Collects attack success rates at different scales, suitable for plotting.
"""
from __future__ import annotations

import csv
import json
import subprocess
from pathlib import Path

SCALES = [2, 4, 8, 16, 32]
ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "prototype" / "mktme_isolation_demo.py"
OUT = ROOT / "artifacts" / "batch"


def run_scale(scale: int) -> dict:
    out_dir = OUT / f"c{scale}"
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["python3", str(DEMO), "--containers", str(scale), "--output", str(out_dir)]
    cp = subprocess.run(cmd, cwd=ROOT, check=True, capture_output=True, text=True)
    return json.loads(cp.stdout)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    for scale in SCALES:
        report = run_scale(scale)
        rows.append(
            {
                "containers": report["container_count"],
                "mode": report["mode"],
                "successful_attacks": report["successful_attacks"],
            }
        )

    csv_path = OUT / "summary.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["containers", "mode", "successful_attacks"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"wrote {csv_path}")


if __name__ == "__main__":
    main()
