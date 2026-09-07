#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WARDEN-11 report packer.

Creates a simple zip archive from generated reports.
"""

from __future__ import annotations

import argparse
import zipfile
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("reports_dir", help="Directory containing WARDEN-11 reports")
    parser.add_argument("--out", default="warden11_report_pack.zip")
    args = parser.parse_args()

    reports = Path(args.reports_dir)
    out = Path(args.out)

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for file in reports.rglob("*"):
            if file.is_file():
                z.write(file, arcname=file.relative_to(reports))

    print(f"written: {out}")


if __name__ == "__main__":
    main()
