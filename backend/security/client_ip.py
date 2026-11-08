from __future__ import annotations

import ipaddress
import os
from typing import Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

TRUSTED_PROXIES_ENV = "ELDORADO_TRUSTED_PROXIES"

# A legitimate proxy chain is short. Anything longer is treated as hostile.
_MAX_FORWARDED_HOPS = 20


def parse_trusted_proxies(raw: str | None) -> tuple[IPNetwork, ...]:
    """
    Parse a comma-separated list of proxy addresses or CIDR networks.

    Fails closed: an invalid entry, or a network that would trust every
    address, raises RuntimeError rather than silently weakening the
    rate limiter.
    """
    if raw is None or not raw.strip():
        return ()

    networks: list[IPNetwork] = []

    for item in raw.split(","):
        item = item.strip()

        if not item:
            continue

        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise RuntimeError(
                f"{TRUSTED_PROXIES_ENV} contains an invalid entry."
            ) from None

        if network.prefixlen == 0:
            raise RuntimeError(
                f"{TRUSTED_PROXIES_ENV} must not trust every address."
            )

        networks.append(network)

    return tuple(networks)


def trusted_proxies_from_env() -> tuple[IPNetwork, ...]:
    return parse_trusted_proxies(os.environ.get(TRUSTED_PROXIES_ENV))


def _parse_ip(value: str) -> IPAddress | None:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped

    return address


def _is_trusted(address: IPAddress, trusted: tuple[IPNetwork, ...]) -> bool:
    return any(address in network for network in trusted)


def resolve_client_ip(
    peer: str | None,
    forwarded_for: str | None,
    trusted: tuple[IPNetwork, ...],
) -> str:
    """
    Return the address to use as the rate-limit identity for a request.

    X-Forwarded-For is attacker-controlled unless it was appended by a
    proxy we trust, so it is only consulted when the direct peer is a
    configured trusted proxy. The chain is then walked right to left and
    the first address that is not itself a trusted proxy is the client;
    anything further left can be forged by the caller and is ignored.
    Any malformed or oversized chain falls back to the direct peer, which
    can only make clients share a bucket, never evade one.
    """
    if not peer:
        return "unknown"

    peer_ip = _parse_ip(peer)

    if peer_ip is None or not trusted or not _is_trusted(peer_ip, trusted):
        return peer

    if not forwarded_for or not forwarded_for.strip():
        return peer

    hops = [hop.strip() for hop in forwarded_for.split(",")]

    if len(hops) > _MAX_FORWARDED_HOPS:
        return peer

    for hop in reversed(hops):
        address = _parse_ip(hop)

        if address is None:
            return peer

        if not _is_trusted(address, trusted):
            return str(address)

    return peer