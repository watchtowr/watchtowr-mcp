import pytest
from ._helpers import assert_ok


@pytest.mark.live
def test_get_asset_dns_records(live_env, call):
    import re
    domains = call("list_asset_domains", page_size=1)
    match = re.search(r'Name:\s*(\S+)', domains)
    if not match:
        pytest.skip("no domains found to test with")
    domain_name = match.group(1)
    response = call("get_asset_dns_records", asset_name=domain_name)
    assert_ok(response)


@pytest.mark.live
def test_search_dns_records(live_env, call):
    response = call("search_dns_records", page_size=5)
    assert_ok(response)


@pytest.mark.live
def test_search_dns_records_by_type(live_env, call):
    response = call("search_dns_records", record_types="A", page_size=5)
    assert_ok(response)
