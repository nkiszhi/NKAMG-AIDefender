"""Audit raw retrain CSVs without loading model/backend dependencies."""
try:
    from .retrain_manifest import main
except ImportError:
    from retrain_manifest import main

if __name__ == "__main__":
    raise SystemExit(main(select=False))
