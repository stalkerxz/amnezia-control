#!/usr/bin/env python3
"""Restricted SSH bridge to local AWG3/AWG4 Unix-socket agents.

The bridge deliberately exposes only a fixed operation allowlist and fixed
runtime/config paths. It is intended to be installed as:

    /usr/local/sbin/amnezia-control-agent-call

Invocation:

    amnezia-control-agent-call <awg3|awg4> <urlsafe-base64-json>

The JSON payload must contain an ``op`` key. Successful responses are printed
as a JSON object to stdout. Failures are printed to stderr and exit non-zero.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import socket
import sys
from pathlib import Path
from typing import Any


AGENTS = {
    "awg3": {
        "socket": Path("/run/awg3-agent/agent.sock"),
        "config": Path("/etc/amnezia/amneziawg/awg3.conf"),
        "interface": "awg3",
    },
    "awg4": {
        "socket": Path("/run/awg4-agent/agent.sock"),
        "config": Path("/etc/amnezia/amneziawg/awg4.conf"),
        "interface": "awg4",
    },
}

FORWARDED_OPS = {
    "health",
    "create_peer",
    "suspend_peer",
    "activate_peer",
    "reserve_peer",
    "revoke_peer",
    "peer_statuses",
}

LOCAL_OPS = {
    "runtime_info",
    "list_peers",
}

PAYLOAD_KEYS = {
    "health": set(),
    "peer_statuses": set(),
    "runtime_info": set(),
    "list_peers": set(),
    "create_peer": {"client_id", "client_name", "mode", "allowed_ips"},
    "suspend_peer": {"public_key", "client_id"},
    "activate_peer": {"public_key", "address", "client_id", "client_name"},
    "reserve_peer": {"public_key", "address", "client_id"},
    "revoke_peer": {"public_key", "client_id"},
}

AWG2_METADATA_KEYS = (
    "Jc",
    "Jmin",
    "Jmax",
    "S1",
    "S2",
    "S3",
    "S4",
    "H1",
    "H2",
    "H3",
    "H4",
    "I1",
    "I2",
    "I3",
    "I4",
    "I5",
    "HeaderProtectionKey",
    "ContentPaddingAddition",
    "RekeyAfterTime",
    "RekeyTimeout",
    "RejectAfterTime",
    "KeepaliveTimeout",
    "MaxHandshakeAttempts",
    "RandomTrailers",
    "DisableCookies",
)

MAX_TOKEN_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


def fail(message: str, code: int = 1) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(code)


def decode_payload(token: str) -> dict[str, Any]:
    if not token or len(token) > MAX_TOKEN_BYTES:
        fail("invalid payload token")

    padding = "=" * (-len(token) % 4)
    try:
        raw = base64.urlsafe_b64decode((token + padding).encode("ascii"))
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        fail("invalid payload encoding")

    if not isinstance(payload, dict):
        fail("payload must be a JSON object")
    return payload


def validate_payload(payload: dict[str, Any]) -> str:
    op = payload.get("op")
    if not isinstance(op, str) or op not in FORWARDED_OPS | LOCAL_OPS:
        fail("unsupported operation")

    allowed = {"op"} | PAYLOAD_KEYS[op]
    unknown = set(payload) - allowed
    if unknown:
        fail("unsupported payload keys")

    for key, value in payload.items():
        if key == "op":
            continue
        if isinstance(value, str):
            if len(value) > 4096 or "\x00" in value:
                fail(f"invalid value for {key}")
        elif isinstance(value, list):
            if len(value) > 2048:
                fail(f"too many values for {key}")
            if not all(isinstance(item, str) and len(item) <= 256 for item in value):
                fail(f"invalid list for {key}")
        else:
            fail(f"invalid type for {key}")

    return op


def parse_config(path: Path) -> tuple[dict[str, str], list[dict[str, str]]]:
    interface: dict[str, str] = {}
    peers: list[dict[str, str]] = []
    section = ""
    current_peer: dict[str, str] = {}

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        text = raw_line.strip()
        if not text or text.startswith("#"):
            continue

        if text.startswith("[") and text.endswith("]"):
            if section.lower() == "peer" and current_peer:
                peers.append(current_peer)
            section = text[1:-1].strip()
            current_peer = {}
            continue

        if "=" not in text:
            continue

        key, value = [part.strip() for part in text.split("=", 1)]
        if section.lower() == "interface":
            if key != "PrivateKey":
                interface[key] = value
        elif section.lower() == "peer":
            if key in {"PublicKey", "AllowedIPs"}:
                current_peer[key] = value

    if section.lower() == "peer" and current_peer:
        peers.append(current_peer)

    return interface, peers


def subnet_from_address(value: str) -> str:
    if not value:
        return ""
    first = value.split(",", 1)[0].strip()
    try:
        return str(ipaddress.ip_interface(first).network)
    except ValueError:
        return ""


def local_runtime_info(agent_name: str) -> dict[str, Any]:
    spec = AGENTS[agent_name]
    interface, peers = parse_config(spec["config"])
    health = forward(agent_name, {"op": "health"})

    listen_port = health.get("listen_port") or interface.get("ListenPort")
    try:
        listen_port = int(listen_port) if listen_port else None
    except (TypeError, ValueError):
        listen_port = None

    return {
        "backend": "awg_agent",
        "agent": agent_name,
        "interface": health.get("interface") or spec["interface"],
        "interface_up": bool(health.get("interface_up")),
        "config_path": str(spec["config"]),
        "listen_port": listen_port,
        "udp_port": listen_port,
        "subnet": subnet_from_address(interface.get("Address", "")),
        "interface_addresses": [interface.get("Address", "")] if interface.get("Address") else [],
        "peer_count": len(peers),
        "reservation_count": int(health.get("reservation_count") or 0),
        "awg2_metadata": {
            key: interface[key]
            for key in AWG2_METADATA_KEYS
            if interface.get(key)
        },
    }


def local_list_peers(agent_name: str) -> dict[str, Any]:
    _, peers = parse_config(AGENTS[agent_name]["config"])
    normalized = []
    for peer in peers:
        public_key = peer.get("PublicKey", "").strip()
        allowed_ips = peer.get("AllowedIPs", "").strip()
        if public_key and allowed_ips:
            normalized.append({
                "public_key": public_key,
                "allowed_ips": allowed_ips,
            })
    return {"peers": normalized}


def forward(agent_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    socket_path = AGENTS[agent_name]["socket"]
    raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")

    chunks: list[bytes] = []
    total = 0
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(20.0)
        client.connect(str(socket_path))
        client.sendall(raw)

        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                fail("agent response too large")
            if b"\n" in chunk:
                break

    if not chunks:
        fail("agent returned an empty response")

    try:
        response = json.loads(b"".join(chunks).split(b"\n", 1)[0])
    except Exception:
        fail("agent returned invalid JSON")

    if not isinstance(response, dict) or not response.get("ok"):
        error = response.get("error") if isinstance(response, dict) else None
        fail(str(error or "agent request failed"))

    result = response.get("result", {})
    if not isinstance(result, dict):
        fail("agent returned invalid result")
    return result


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: amnezia-control-agent-call <awg3|awg4> <payload>", 2)

    agent_name, token = sys.argv[1], sys.argv[2]
    if agent_name not in AGENTS:
        fail("unsupported agent")

    payload = decode_payload(token)
    op = validate_payload(payload)

    if op == "runtime_info":
        result = local_runtime_info(agent_name)
    elif op == "list_peers":
        result = local_list_peers(agent_name)
    else:
        result = forward(agent_name, payload)

    print(json.dumps(result, separators=(",", ":"), ensure_ascii=False))


if __name__ == "__main__":
    main()
