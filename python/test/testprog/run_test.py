#!/usr/bin/env python3
"""Test script to generate summaries and restore empty specs file."""
import subprocess
import sys
import shutil
from pathlib import Path

SPECS_FILE = Path(__file__).parent / "specs.yaml"
EMPTY_SPECS = "dataflow-summaries: []\n"

def main():
    # Backup current specs
    backup = SPECS_FILE.read_text()
    
    try:
        # Run summary generator
        cmd = [
            sys.executable, "-m", "summary_generator.generate",
            "--config", str(Path(__file__).parent / "config.yaml"),
            "--target", "main",
            "--functions", str(Path(__file__).parent / "functions.json"),
            "--output", str(Path(__file__).parent / "specs.yaml")
        ]
        
        print(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, cwd=Path(__file__).parent.parent.parent, check=True)
        
        print("\n✓ Summaries generated and verified successfully")
        
    except subprocess.CalledProcessError as e:
        print(f"\n✗ Summary generation failed: {e}", file=sys.stderr)
        SPECS_FILE.write_text(backup)
        return 1
    
    finally:
        # Restore empty specs
        print("\nRestoring empty specs file...")
        SPECS_FILE.write_text(EMPTY_SPECS)
        print("✓ Specs file restored")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
