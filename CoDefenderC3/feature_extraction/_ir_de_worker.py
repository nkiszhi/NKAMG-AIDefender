"""Validated D/E worker; deliberately no legacy append-to-NPZ protocol."""
from ._ir_worker import main

if __name__ == "__main__":
    raise SystemExit(main())
