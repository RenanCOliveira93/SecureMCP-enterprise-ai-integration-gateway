"""Every setting is documented, and the documentation does not describe settings that no longer exist."""

import re

from securemcp.config import Settings
from securemcp.security.secrets import KNOWN_SECRETS
from tests.helpers import ROOT

DOC = (ROOT / "docs/configuration.md").read_text()


def test_every_setting_is_documented():
    documented = set(re.findall(r"`(SECUREMCP_[A-Z0-9_]+)`", DOC))
    expected = {f"SECUREMCP_{name.upper()}" for name in Settings.model_fields}
    assert expected - documented == set(), "add these to docs/configuration.md"


def test_no_stale_settings_documented():
    documented = set(re.findall(r"^\| `(SECUREMCP_[A-Z0-9_]+)` \|", DOC, re.M))
    known = {f"SECUREMCP_{name.upper()}" for name in Settings.model_fields}
    extra = {
        "SECUREMCP_SECRET_<NAME>",
        "SECUREMCP_TEST_POSTGRES_URL",
        "SECUREMCP_TEST_POSTGRES_APP_URL",
        "SECUREMCP_TEST_BACKEND",
    }
    assert documented - known - extra == set()


def test_every_secret_is_documented():
    for name in KNOWN_SECRETS:
        assert f"| `{name}` |" in DOC
