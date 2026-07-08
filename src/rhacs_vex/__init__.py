"""rhacs_vex — RHACS ↔ Red Hat CSAF-VEX triage engine and tooling.

Clean-room matching engine (``rhacs_vex.engine``) plus the IO / CLI layers that
scan images through RHACS Central, cross-reference Red Hat VEX, and render or
export the verdicts (``triage``, ``operators``, ``retriage``, ``parquet``,
``ns_map``, ``query``, ``pipeline``).

The engine's key API is re-exported here **lazily** (PEP 562 ``__getattr__``):
importing the package must NOT eagerly import ``.engine``.  ``rhacs_vex.retriage``
sets ``VEX_CACHE_SIZE`` before the engine's import-time ``lru_cache`` is created,
and ``python -m rhacs_vex.retriage`` imports this package first — an eager
``from .engine import ...`` here would freeze the engine cache at its 512 default
before retriage's worker bootstrap could shrink it.
"""

__version__ = "1.0.0"

__all__ = [
    "audit_row_detailed",
    "WorkloadContext",
    "parse_image_ref",
    "parse_context_from_labels",
]


def __getattr__(name):
    if name in __all__:
        from . import engine
        return getattr(engine, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(set(globals()) | set(__all__))
