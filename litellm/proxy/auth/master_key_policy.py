"""Startup gate that refuses to boot the proxy with the docs example master key.

The example key ``sk-1234`` appears throughout the docs and example configs, so
deployments copied from them end up publicly reachable with a known credential.
Boot is refused unless ``LITELLM_ALLOW_INSECURE_MASTER_KEY=true`` opts out, which
exists for local development and CI only.
"""

from typing import Final

INSECURE_MASTER_KEYS: Final = frozenset({"sk-1234"})
ALLOW_INSECURE_MASTER_KEY_ENV: Final = "LITELLM_ALLOW_INSECURE_MASTER_KEY"


def insecure_master_key_error(master_key: str | None, allow_insecure: bool) -> str | None:
    if allow_insecure or master_key not in INSECURE_MASTER_KEYS:
        return None
    return (
        "LITELLM_MASTER_KEY is set to the example key 'sk-1234' from the docs. "
        "Publicly reachable gateways using this key have been compromised. "
        "Set a strong random master key (e.g. `python -c \"import secrets; print('sk-' + secrets.token_urlsafe(32))\"`) "
        "or, for local development only, "
        f"set {ALLOW_INSECURE_MASTER_KEY_ENV}=true."
    )


def insecure_master_key_warning(master_key: str | None) -> str | None:
    if master_key not in INSECURE_MASTER_KEYS:
        return None
    return (
        f"LITELLM_MASTER_KEY is set to the insecure example key 'sk-1234' and was "
        f"allowed only because {ALLOW_INSECURE_MASTER_KEY_ENV}=true. Do not use this in production."
    )
