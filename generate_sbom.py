"""Create the SentinelShield release software inventory.

Run: ``python generate_sbom.py`` from the project directory.
"""
from supply_chain import generate


if __name__ == "__main__":
    report = generate()
    print(f"Wrote sentinelshield_sbom.json with {len(report['components'])} components and {len(report['source_files'])} source hashes.")
