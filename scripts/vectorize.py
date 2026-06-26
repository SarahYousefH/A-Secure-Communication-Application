#!/usr/bin/env python3
"""
Parse NIST SHA-256 .rsp files into a JSON test vector file.

Usage:
    python rsp_to_json.py SHA256ShortMsg.rsp SHA256LongMsg.rsp -o sha256_vectors.json

    # Single file:
    python rsp_to_json.py SHA256ShortMsg.rsp

    # Multiple files get merged into one JSON:
    python rsp_to_json.py SHA256ShortMsg.rsp SHA256LongMsg.rsp
"""

# This script was AI generated to help extact test vectors from zip files provided by NIST. 

import argparse
import json
import sys
from pathlib import Path


def parse_rsp(path: Path) -> list[dict]:
    """
    Parse a NIST .rsp file and return a list of test vector dicts.

    The .rsp format looks like:

        [L = 256]

        Len = 0
        Msg = 00
        MD  = e3b0c44298fc1c149afbf4c8996fb924...

        Len = 8
        Msg = d3
        MD  = 28969cdfa74a12c82f3bad960b0b000a...
    """
    vectors = []
    current = {}

    with open(path, "r") as f:
        for raw_line in f:
            line = raw_line.strip()

            # Skip comments and section headers
            if not line or line.startswith("#") or line.startswith("["):
                # If we hit a blank line and have a complete entry, save it
                if current.get("Len") is not None and "Msg" in current and "MD" in current:
                    vectors.append(current)
                    current = {}
                continue

            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()

                if key == "Len":
                    current["Len"] = int(value)
                elif key == "Msg":
                    current["Msg"] = value.lower()
                elif key == "MD":
                    current["MD"] = value.lower()

            # Complete entry when we have all three fields
            if "Len" in current and "Msg" in current and "MD" in current:
                vectors.append(current)
                current = {}

    # Catch last entry if file doesn't end with blank line
    if "Len" in current and "Msg" in current and "MD" in current:
        vectors.append(current)

    return vectors


def rsp_to_test_vectors(rsp_vectors: list[dict], source_file: str) -> list[dict]:
    """
    Convert parsed .rsp entries into the target JSON format.

    NIST quirk: when Len = 0, the Msg field is "00" (a dummy byte),
    but the actual input is an empty byte string b"".
    """
    result = []
    for entry in rsp_vectors:
        bit_len = entry["Len"]
        msg_hex = entry["Msg"]
        md_hex  = entry["MD"]

        # When length is 0, the message is empty — NIST uses "00" as placeholder
        if bit_len == 0:
            input_hex = ""
            description = f"Empty input (Len=0) — from {source_file}"
        else:
            # Trim msg_hex to exactly bit_len bits (byte_len bytes)
            byte_len = bit_len // 8
            input_hex = msg_hex[:byte_len * 2]
            description = f"Len={bit_len} bits — from {source_file}"

        result.append({
            "description": description,
            "input_hex":   input_hex,
            "output_hex":  md_hex,
        })

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Convert NIST SHA-256 .rsp files to a JSON test vector file."
    )
    parser.add_argument(
        "rsp_files",
        nargs="+",
        metavar="FILE.rsp",
        help="One or more NIST .rsp files to parse",
    )
    parser.add_argument(
        "-o", "--output",
        default="sha256_vectors.json",
        metavar="OUTPUT.json",
        help="Output JSON file (default: sha256_vectors.json)",
    )
    args = parser.parse_args()

    all_vectors = []

    for rsp_path_str in args.rsp_files:
        rsp_path = Path(rsp_path_str)
        if not rsp_path.exists():
            print(f"ERROR: file not found: {rsp_path}", file=sys.stderr)
            sys.exit(1)

        print(f"Parsing {rsp_path} ...", end=" ")
        rsp_entries = parse_rsp(rsp_path)
        vectors     = rsp_to_test_vectors(rsp_entries, rsp_path.name)
        all_vectors.extend(vectors)
        print(f"{len(vectors)} vectors found")

    output_path = Path(args.output)
    with open(output_path, "w") as f:
        json.dump(all_vectors, f, indent=2)

    print(f"\nDone. {len(all_vectors)} total vectors written to {output_path}")
    print("\nFirst entry preview:")
    if all_vectors:
        print(json.dumps(all_vectors[0], indent=2))


if __name__ == "__main__":
    main()