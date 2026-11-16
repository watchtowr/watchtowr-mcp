"""Record Client API responses for test/unit/test_client_api_contract.py.

Point it at a non-production tenant, then read every file it writes before committing:
the fixtures ship with the public repo.

    uv run --env-file .env python test/record_client_api_responses.py [out_dir]
"""
from __future__ import annotations

import importlib
import inspect
import ipaddress
import json
import os
import re
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent / "unit"))
os.environ["WATCHTOWR_MCP_READ_ONLY"] = "true"

import watchtowr_api_sdk.models as sdk_models  # noqa: E402
from pydantic import BaseModel  # noqa: E402
from test_sdk_surface import SDK_CALLS  # noqa: E402

from watchtowr_mcp_server.client import get_api_client  # noqa: E402
from watchtowr_mcp_server.sdk_compat import apply_watchtowr_sdk_compat_patches  # noqa: E402

OUT_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "unit" / "client_api_responses"
ITEMS_KEPT_PER_LIST = 2

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6 = re.compile(r"(?<![\w:])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![\w:])", re.IGNORECASE)
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
HOSTNAME = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:[a-z]{2,}|xn--[a-z0-9-]+)\b", re.IGNORECASE)
KEPT_HOSTS = {"example.com", "example.net", "example.org"}
REDACTED_KEYS = {
    "name", "requested_by", "completed_by", "username", "hostname", "malwarePath", "businessUnitName",
    "description", "evidence", "raw", "raw_referral", "address", "org", "asn_description",
    "subjectOrganisation", "subjectCommonName", "publisher", "owner", "stealerId", "discoveryValue", "author",
    "handle", "asn", "city", "postal_code",
}
SDK_KEYS = {
    field.alias or name
    for model in vars(sdk_models).values()
    if isinstance(model, type) and issubclass(model, BaseModel)
    for name, field in model.model_fields.items()
}


class Anonymiser:
    def __init__(self):
        self.ips: dict[str, str] = {}
        self.hosts: dict[str, str] = {}
        self.redacted: dict[str, str] = {}

    def ip(self, match: re.Match) -> str:
        try:
            address = ipaddress.ip_address(match.group())
        except ValueError:
            return match.group()
        if address.is_loopback:
            return match.group()
        documentation_address = "192.0.2.{}" if address.version == 4 else "2001:db8::{:x}"
        return self.ips.setdefault(match.group(), documentation_address.format(len(self.ips) % 254 + 1))

    def host(self, match: re.Match) -> str:
        name = match.group().lower()
        if any(name == kept or name.endswith(f".{kept}") for kept in KEPT_HOSTS):
            return match.group()
        return self.hosts.setdefault(name, f"host{len(self.hosts) + 1}.example.com")

    def text(self, value: str) -> str:
        value = EMAIL.sub("user@example.com", value)
        value = IPV6.sub(self.ip, IPV4.sub(self.ip, value))
        return HOSTNAME.sub(self.host, value)

    def redact(self, value):
        if isinstance(value, list):
            return [self.redact(item) for item in value[:ITEMS_KEPT_PER_LIST]]
        if not isinstance(value, str) or value in ("", "-"):
            return self(value)
        return self.redacted.setdefault(value, f"redacted-{len(self.redacted) + 1}")

    def __call__(self, value):
        if isinstance(value, dict):
            return {
                key: self.redact(item) if key in REDACTED_KEYS or key not in SDK_KEYS else self(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self(item) for item in value[:ITEMS_KEPT_PER_LIST]]
        if isinstance(value, str):
            return self.text(value)
        return value


def first_id(recorded: dict, method_name: str, field: str = "id"):
    data = recorded.get(method_name, {}).get("response", {}).get("data")
    value = data[0].get(field) if isinstance(data, list) and data else None
    return int(value) if isinstance(value, str) and value.isdigit() else value


def from_first_item(list_method: str, param: str = "id", field: str = "id"):
    return lambda recorded: {param: first_id(recorded, list_method, field)}


KWARGS_FOR = {
    "show_the_detail_hunt": from_first_item("get_client_hunts"),
    "get_list_finding_by_hunt": from_first_item("get_client_hunts"),
    "get_list_asset_by_hunt": from_first_item("get_client_hunts"),
    "get_asset_ip_ports": from_first_item("get_list_asset_ips"),
    "get_asset_ip_port_details": lambda recorded: {
        "ip_id": recorded.get("get_asset_ip_ports", {}).get("kwargs", {}).get("id"),
        "port_id": first_id(recorded, "get_asset_ip_ports"),
    },
    "get_vulnerability_intelligence_details": from_first_item(
        "get_list_vulnerability_intelligence", "identifier", "identifier"
    ),
    "get_adversary_intelligence_details": from_first_item("get_list_adversary_intelligence", "attacker_id"),
    "get_list_compromised_endpoint_harvested_credentials": from_first_item("get_list_compromised_endpoints"),
    "capability_search": lambda recorded: {"query": "apache"},
}


def record() -> None:
    apply_watchtowr_sdk_compat_patches()
    api_client = get_api_client()
    sdk_deserialize = api_client.response_deserialize
    reply = {}

    def keep_raw_reply(response_data, response_types_map=None):
        reply.update(status=response_data.status, body=response_data.data, rejected=None)
        try:
            sdk_deserialize(response_data, response_types_map)
        except Exception as error:
            reply["rejected"] = error
        return SimpleNamespace(data=None)

    api_client.response_deserialize = keep_raw_reply
    anonymise = Anonymiser()
    recorded: dict[str, dict] = {}
    gets = []
    for module, class_name, method_name in SDK_CALLS:
        api_class = getattr(importlib.import_module(module), class_name)
        serializer = inspect.getsource(getattr(api_class, f"_{method_name}_serialize"))
        if "method='GET'" in serializer:
            gets.append((class_name, api_class, method_name))
    gets.sort(key=lambda call: call[2] in KWARGS_FOR or "id" in inspect.signature(getattr(call[1], call[2])).parameters)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for class_name, api_class, method_name in gets:
        method = getattr(api_class(api_client), method_name)
        kwargs = {}
        if method_name in KWARGS_FOR:
            kwargs = KWARGS_FOR[method_name](recorded)
        elif "id" in inspect.signature(method).parameters:
            list_method = next(name for _, cls, name in gets if cls is api_class and name.startswith("get_list_"))
            kwargs = {"id": first_id(recorded, list_method)}
        if None in kwargs.values():
            print(f"skipped {method_name}: no item to take an id from")
            continue
        method(**kwargs)
        if reply["status"] != 200:
            print(f"skipped {method_name}: HTTP {reply['status']}")
            continue
        recorded[method_name] = {"kwargs": kwargs, "response": json.loads(reply["body"])}
        fixture = {"api": class_name, "method": method_name, "kwargs": kwargs, "response": anonymise(recorded[method_name]["response"])}
        (OUT_DIR / f"{method_name}.json").write_text(json.dumps(fixture, indent=2, ensure_ascii=False) + "\n")
        print(f"recorded {method_name}")
        if reply["rejected"]:
            print(f"  the SDK rejects the full page {method_name} returned: {reply['rejected']}")


if __name__ == "__main__":
    record()
