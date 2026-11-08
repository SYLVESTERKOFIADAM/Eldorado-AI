from __future__ import annotations

import pytest
from starlette.requests import Request

from backend.api.auth_routes import get_client_ip
from backend.security.client_ip import (
    parse_trusted_proxies,
    resolve_client_ip,
    trusted_proxies_from_env,
)

PROXIES = parse_trusted_proxies("10.0.0.0/8")


def _request(peer: str, forwarded: str | None = None) -> Request:
    headers = []
    if forwarded is not None:
        headers.append((b"x-forwarded-for", forwarded.encode()))
    return Request(
        {"type": "http", "headers": headers, "client": (peer, 5555)}
    )


# --- parse_trusted_proxies -------------------------------------------------


def test_parse_returns_empty_when_unset_or_blank() -> None:
    assert parse_trusted_proxies(None) == ()
    assert parse_trusted_proxies("") == ()
    assert parse_trusted_proxies("  ,  ") == ()


def test_parse_accepts_addresses_and_networks() -> None:
    networks = parse_trusted_proxies("10.0.0.1, 192.168.0.0/16 ,::1")

    assert len(networks) == 3


def test_parse_rejects_invalid_entry() -> None:
    with pytest.raises(RuntimeError):
        parse_trusted_proxies("10.0.0.1, not-an-ip")


@pytest.mark.parametrize("entry", ["0.0.0.0/0", "::/0"])
def test_parse_rejects_trust_everything_networks(entry: str) -> None:
    with pytest.raises(RuntimeError):
        parse_trusted_proxies(entry)


# --- resolve_client_ip -----------------------------------------------------


def test_header_ignored_when_no_trusted_proxies_configured() -> None:
    assert resolve_client_ip("198.51.100.9", "203.0.113.7", ()) == (
        "198.51.100.9"
    )


def test_header_ignored_when_peer_is_not_trusted() -> None:
    assert resolve_client_ip("198.51.100.9", "203.0.113.7", PROXIES) == (
        "198.51.100.9"
    )


def test_header_used_when_peer_is_trusted() -> None:
    assert resolve_client_ip("10.0.0.1", "203.0.113.7", PROXIES) == (
        "203.0.113.7"
    )


def test_spoofed_leftmost_hop_is_ignored() -> None:
    result = resolve_client_ip(
        "10.0.0.1",
        "9.9.9.9, 203.0.113.7, 10.0.0.2",
        PROXIES,
    )

    assert result == "203.0.113.7"


def test_peer_returned_when_header_missing() -> None:
    assert resolve_client_ip("10.0.0.1", None, PROXIES) == "10.0.0.1"
    assert resolve_client_ip("10.0.0.1", "", PROXIES) == "10.0.0.1"


def test_peer_returned_when_every_hop_is_trusted() -> None:
    assert resolve_client_ip("10.0.0.1", "10.0.0.2, 10.0.0.3", PROXIES) == (
        "10.0.0.1"
    )


def test_peer_returned_when_chain_is_malformed() -> None:
    assert resolve_client_ip("10.0.0.1", "203.0.113.7, garbage", PROXIES) == (
        "10.0.0.1"
    )


def test_peer_returned_when_chain_is_absurdly_long() -> None:
    chain = ", ".join(["203.0.113.7"] * 50)

    assert resolve_client_ip("10.0.0.1", chain, PROXIES) == "10.0.0.1"


def test_ipv4_mapped_ipv6_is_normalised() -> None:
    assert resolve_client_ip(
        "10.0.0.1", "::ffff:203.0.113.7", PROXIES
    ) == "203.0.113.7"


def test_unknown_when_peer_missing() -> None:
    assert resolve_client_ip(None, "203.0.113.7", PROXIES) == "unknown"


def test_non_ip_peer_is_returned_unchanged() -> None:
    assert resolve_client_ip("testclient", "203.0.113.7", PROXIES) == (
        "testclient"
    )


# --- environment + FastAPI dependency --------------------------------------


def test_trusted_proxies_read_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ELDORADO_TRUSTED_PROXIES", "10.0.0.1")

    assert len(trusted_proxies_from_env()) == 1


def test_get_client_ip_ignores_header_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ELDORADO_TRUSTED_PROXIES", raising=False)

    request = _request("10.0.0.1", "203.0.113.7")

    assert get_client_ip(request) == "10.0.0.1"


def test_get_client_ip_honours_header_from_trusted_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ELDORADO_TRUSTED_PROXIES", "10.0.0.1")

    request = _request("10.0.0.1", "203.0.113.7")

    assert get_client_ip(request) == "203.0.113.7"


def test_get_client_ip_fails_closed_on_invalid_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ELDORADO_TRUSTED_PROXIES", "bogus")

    with pytest.raises(RuntimeError):
        get_client_ip(_request("10.0.0.1"))