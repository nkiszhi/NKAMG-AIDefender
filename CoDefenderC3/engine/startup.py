"""Engine entrypoint defaults; workers inherit the chosen backend unchanged."""
import os


def configure_disassembly_backend(environ=None):
    env = os.environ if environ is None else environ
    value = str(env.get("CODEFENDER_DISASM_BACKEND", "")).strip().lower() or "smda"
    if value not in {"smda", "bn"}:
        raise ValueError("CODEFENDER_DISASM_BACKEND must be smda or bn, got: " + repr(value))
    env["CODEFENDER_DISASM_BACKEND"] = value
    return value


if __name__ == "__main__":
    print(configure_disassembly_backend())
