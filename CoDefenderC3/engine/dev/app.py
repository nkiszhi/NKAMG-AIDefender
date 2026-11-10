"""test_lm development API; detailed results, shared main inference core."""
import engine.app as core
from engine.contract_app import create_app

app = create_app(core, development=True)
