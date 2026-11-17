"""Compatibility import: the feature/layout implementation lives in runtime code."""
from pathlib import Path
import sys
# Direct one-sample workers start with train/ on sys.path, not the project root.
_project = str(Path(__file__).resolve().parents[1])
if _project not in sys.path:
    sys.path.insert(0, _project)
from engine.feature_contract import (FeatureContract, ContractError, canonical, digest,
                                     numeric_dtype, SCHEMA, SHA_RE, NAME_RE)
