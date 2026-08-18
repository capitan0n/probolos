"""Probolos — a USB authorization gate that judges devices, not just IDs."""

# The version lived in two places (here and pyproject.toml) and drifted: this
# file said 0.5.1 while the package metadata said 0.9.0. Rather than fix the
# instance, remove the class of bug -- pyproject.toml is now the single source
# and this reads it back at runtime. The literal below is only reached when the
# package is not installed (running straight from a source checkout), and is
# marked as such so it can never again be mistaken for the real version.

__all__ = ["__version__"]

try:
    from importlib.metadata import PackageNotFoundError, version as _version

    __version__ = _version("probolos")
except Exception:  # not installed: source checkout, or metadata unavailable
    __version__ = "0.9.0+source"
