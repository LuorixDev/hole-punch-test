import os
import sys
from pathlib import Path

# A source checkout can reuse its installed dependencies without shell activation.
if __name__ == "__main__" and not getattr(sys, "frozen", False) and sys.prefix == sys.base_prefix:
    runtime = Path(__file__).resolve().parent / ".venv"
    python = runtime / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if python.is_file():
        os.execv(str(python), [str(python), str(Path(__file__).resolve()), *sys.argv[1:]])

from p2plab.client import main

if __name__ == "__main__":
    main()
