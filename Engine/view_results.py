# engine/view_results.py
import json
import sys
from tabulate import tabulate

def load(path="scan_results.json"):
    with open(path, "r") as f:
        return json.load(f)

def flatten(results):
    rows = []
    for host, services in results.items():
        for s in services:
            banner = s.get("banner") or ""
            rows.append([host, s.get("port"), (banner[:80] + "...") if len(banner) > 80 else banner])
    return rows

def main(path="scan_results.json"):
    try:
        results = load(path)
    except FileNotFoundError:
        print(f"No results file found at {path}. Run the scanner first.")
        return
    rows = flatten(results)
    if not rows:
        print("No open ports found in results.")
        return
    print(tabulate(rows, headers=["Host", "Port", "Banner"], tablefmt="github"))

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--file", default="scan_results.json")
    args = p.parse_args()
    main(args.file)
