import pytest
from ._helpers import assert_ok

pytestmark = pytest.mark.live


def test_get_asset_changelog(live_env, call, sample_domain_id):
    response = call("get_asset_changelog", asset_type="domain", asset_id=sample_domain_id)
    assert_ok(response, allow_empty=True)


def test_get_asset_changelog_invalid_id(live_env, call):
    response = call("get_asset_changelog", asset_type="domain", asset_id=999999)
    # Should return empty or error gracefully
    assert isinstance(response, str)
