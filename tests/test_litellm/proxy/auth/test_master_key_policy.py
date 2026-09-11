from litellm.proxy.auth.master_key_policy import (
    insecure_master_key_error,
    insecure_master_key_warning,
)


def test_insecure_master_key_error_refuses_example_key():
    error = insecure_master_key_error(master_key="sk-1234", allow_insecure=False)
    assert error is not None
    assert "sk-1234" in error
    assert "LITELLM_ALLOW_INSECURE_MASTER_KEY" in error


def test_insecure_master_key_error_allows_with_escape_hatch():
    assert insecure_master_key_error(master_key="sk-1234", allow_insecure=True) is None


def test_insecure_master_key_error_allows_strong_key():
    assert insecure_master_key_error(master_key="sk-strong-random-key", allow_insecure=False) is None


def test_insecure_master_key_error_allows_missing_key():
    assert insecure_master_key_error(master_key=None, allow_insecure=False) is None


def test_insecure_master_key_warning_only_for_example_key():
    assert insecure_master_key_warning(master_key="sk-1234") is not None
    assert insecure_master_key_warning(master_key="sk-strong-random-key") is None
    assert insecure_master_key_warning(master_key=None) is None


def test_remediation_hint_survives_log_redaction():
    from litellm.litellm_core_utils.secret_redaction import redact_string

    error = insecure_master_key_error(master_key="sk-1234", allow_insecure=False)
    warning = insecure_master_key_warning(master_key="sk-1234")
    assert error is not None and warning is not None
    assert "LITELLM_ALLOW_INSECURE_MASTER_KEY" in redact_string(error)
    assert "LITELLM_ALLOW_INSECURE_MASTER_KEY" in redact_string(warning)
