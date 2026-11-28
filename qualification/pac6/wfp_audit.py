"""Match Windows Filtering Platform events to the isolated Python probe."""

import argparse
from collections.abc import Iterable, Mapping
from ipaddress import IPv4Address, IPv6Address, ip_address
import json
import ntpath
from pathlib import Path
import sys


def _integer(value: object) -> int | None:
    """Read decimal or hexadecimal event fields as integers."""
    if isinstance(value, bool):
        return None
    try:
        text = str(value).strip()
        return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    except (TypeError, ValueError):
        return None


def _address(value: object) -> IPv4Address | IPv6Address | None:
    """Normalize IP addresses, including IPv4-mapped IPv6 event values."""
    try:
        address = ip_address(str(value).strip())
    except ValueError:
        return None
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def normalized_nt_path(value: object) -> str | None:
    """Normalize a full Windows NT device path and reject non-device paths."""
    path = ntpath.normcase(ntpath.normpath(str(value).strip()))
    prefix = r"\device\harddiskvolume"
    if not path.startswith(prefix):
        return None
    volume, separator, remainder = path[len(prefix) :].partition("\\")
    if not volume.isdecimal() or not separator or not remainder:
        return None
    return path


def has_matching_wfp_block(
    events: Iterable[Mapping[str, object]],
    *,
    process_id: int,
    python_nt_path: str,
    destination_address: str,
    destination_port: int,
    firewall_rule_name: str,
) -> bool:
    """Return true only for a 5157 event matching this TCP probe process."""
    expected_process = _integer(process_id)
    expected_application = normalized_nt_path(python_nt_path)
    expected_address = _address(destination_address)
    expected_port = _integer(destination_port)
    expected_rule = firewall_rule_name.casefold()
    if (
        expected_process is None
        or expected_application is None
        or expected_address is None
        or expected_port is None
        or not expected_rule
    ):
        return False

    for event in events:
        process = _integer(event.get("process_id"))
        event_address = _address(event.get("destination_address"))
        if (
            _integer(event.get("event_id")) == 5157
            and process == expected_process
            and normalized_nt_path(event.get("application")) == expected_application
            and event_address == expected_address
            and _integer(event.get("destination_port")) == expected_port
            and _integer(event.get("protocol")) == 6
            and str(event.get("filter_origin", "")).casefold() == expected_rule
        ):
            return True
    return False


def main() -> int:
    """Validate a captured event set and print its matching block record."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--process-id", required=True, type=int)
    parser.add_argument("--python-nt-path", required=True)
    parser.add_argument("--destination-address", required=True)
    parser.add_argument("--destination-port", required=True, type=int)
    parser.add_argument("--firewall-rule-name", required=True)
    args = parser.parse_args()

    try:
        events = json.loads(args.events.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"Unable to read WFP event evidence: {error}", file=sys.stderr)
        return 2
    if not isinstance(events, list):
        print("WFP event evidence must be a JSON array.", file=sys.stderr)
        return 2

    matching_event = next(
        (
            event
            for event in events
            if isinstance(event, Mapping)
            and has_matching_wfp_block(
                [event],
                process_id=args.process_id,
                python_nt_path=args.python_nt_path,
                destination_address=args.destination_address,
                destination_port=args.destination_port,
                firewall_rule_name=args.firewall_rule_name,
            )
        ),
        None,
    )
    if matching_event is None:
        print("No WFP block event matched the probe process and endpoint.", file=sys.stderr)
        return 1

    print(json.dumps({"matched": True, "matching_event": matching_event}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
