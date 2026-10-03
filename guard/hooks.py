"""The components behind hook.py, by name.

Each takes the hook payload and returns the JSON to print, or None for no
decision. Every run leaves a heartbeat (state_dir/heartbeats/<component>), so
the doctor can tell a hook that's installed from one that actually fires.
Anything that goes wrong here is caught by hook.py, which then exits 0 with no
output: hooks fail open, and the detective components (the effect check, the
tripwire, the doctor) cover what a failed hook misses.

Each component's module is imported only when its hook runs: every tool call
pays for what it imports, and the doctor, for one, has no place in that path.
"""

from __future__ import annotations

import os
import time

from . import config


def _policy(payload: dict, cfg: config.Config):
    """C4 first (it binds every agent), then C1."""
    from . import policy, selfprotect

    return selfprotect.decide(payload, cfg) or policy.decide(payload, cfg)


def _effect_pre(payload: dict, cfg: config.Config):
    from . import effect

    return effect.pre(payload, cfg)


def _effect_post(payload: dict, cfg: config.Config):
    from . import effect

    return effect.post(payload, cfg)


def _config_change(payload: dict, cfg: config.Config):
    from . import selfprotect

    return selfprotect.config_change(payload, cfg)


def _doctor_fast(payload: dict, cfg: config.Config):
    from . import doctor

    return doctor.fast(payload, cfg)


COMPONENTS = {
    "policy": _policy,
    "effect-pre": _effect_pre,
    "effect-post": _effect_post,
    "config-change": _config_change,
    "doctor-fast": _doctor_fast,
}


def heartbeat(cfg: config.Config, component: str) -> None:
    d = config.ensure_state_dir(cfg) / "heartbeats"
    d.mkdir(exist_ok=True)
    os.chmod(d, 0o700)
    (d / component).write_text(f"{time.time():.3f}\n")


def run(component: str, payload: dict) -> dict | None:
    if component not in COMPONENTS:
        raise LookupError(
            f"unknown component {component!r} (known: {', '.join(COMPONENTS)})"
        )
    cfg = config.load()
    heartbeat(cfg, component)
    return COMPONENTS[component](payload, cfg)
