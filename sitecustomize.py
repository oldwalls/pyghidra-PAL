"""Automatic PAL path activation when the PAL root is on PYTHONPATH."""

try:
    import PALenv  # noqa: F401
except Exception:
    # sitecustomize must never prevent Python itself from starting. PAL's
    # explicit launchers and environment checker report actionable failures.
    pass
