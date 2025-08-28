from pathlib import Path
import sys

root = Path(__file__).resolve().parent
examples_dir = root / "examples"
if str(examples_dir) not in sys.path:
    sys.path.insert(0, str(examples_dir))
