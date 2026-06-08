from __future__ import annotations

from pathlib import Path

import streamlit.components.v1 as components


_COMPONENT_DIR = Path(__file__).resolve().parents[2] / "components" / "webauthn_bridge"

_WEBAUTHN_COMPONENT = components.declare_component(
    "webauthn_bridge",
    path=str(_COMPONENT_DIR),
)


def webauthn_bridge(
    *,
    mode: str,
    options_json: str,
    button_label: str,
    key: str,
    disabled: bool = False,
) -> dict | None:
    return _WEBAUTHN_COMPONENT(
        mode=mode,
        optionsJson=options_json,
        buttonLabel=button_label,
        disabled=disabled,
        key=key,
        default=None,
    )
