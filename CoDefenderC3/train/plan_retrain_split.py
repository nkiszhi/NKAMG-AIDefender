"""Generate strictly isolated train/model_val/calibration/test manifests."""
try:
    from .retrain_manifest import main
except ImportError:
    from retrain_manifest import main

if __name__ == "__main__":
    raise SystemExit(main(select=True))
