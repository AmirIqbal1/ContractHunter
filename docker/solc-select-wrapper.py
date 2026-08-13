#!/opt/slither/bin/python
import importlib.metadata
import os
import sys

SOLC_SELECT = "/opt/slither/bin/solc-select"

if sys.argv[1:] == ["--version"]:
    print(importlib.metadata.version("solc-select"))
    raise SystemExit(0)

os.execv(SOLC_SELECT, [SOLC_SELECT, *sys.argv[1:]])
