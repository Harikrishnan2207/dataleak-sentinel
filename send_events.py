"""Send simulated access events to the DataLeak Sentinel API. Standard library only.

Start the API first (see README), then for example:
    python send_events.py demo
    python send_events.py one --user-id U1001 --username aarav.nair --department Finance --records 8

The API key is read from the DATALEAK_API_KEY environment variable (or --key).
All users and events are synthetic.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8000"


def call(method: str, url: str, key: str | None = None, payload: dict | None = None):
    """Return (status_code, parsed_json). Network failures raise SystemExit with a clear message."""
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    if key:
        request.add_header("X-API-Key", key)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8"))
        except Exception:
            body = {"detail": exc.reason}
        return exc.code, body
    except urllib.error.URLError as exc:
        raise SystemExit(f"Cannot reach the API at {url}: {exc.reason}. Is it running?")


def explain(detail) -> str:
    """Turn the API's error detail (text, or a list of validation problems) into one readable line."""
    if isinstance(detail, list):
        return "; ".join(f"{'.'.join(str(p) for p in item.get('loc', [])[1:])}: {item.get('msg')}" for item in detail)
    return str(detail)


def send_event(base: str, key: str, event: dict) -> bool:
    status, body = call("POST", f"{base}/events", key, event)
    who = f"{event['username']:<12} {event['records_accessed']:>7,} records"
    if status == 201:
        alert = f"alert #{body['alert_id']}" if body["alert_id"] else "no alert"
        print(f"  {who} -> {body['risk_level']:<6} score {body['risk_score']:>3}  ({alert})")
        print(f"      {body['reason']}")
        return True
    print(f"  {who} -> REJECTED (HTTP {status}): {explain(body.get('detail'))}")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default=DEFAULT_URL, help=f"API address (default {DEFAULT_URL})")
    parser.add_argument("--key", default=os.environ.get("DATALEAK_API_KEY"), help="API key (or set DATALEAK_API_KEY)")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("demo", help="send one normal access and one bulk extraction")
    one = sub.add_parser("one", help="send a single access")
    one.add_argument("--user-id", required=True)
    one.add_argument("--username", required=True)
    one.add_argument("--department", required=True)
    one.add_argument("--access-type", default="SELECT Query")
    one.add_argument("--records", type=int, required=True)
    one.add_argument("--query", default=None, help="optional SQL text to store in the audit log")
    args = parser.parse_args()
    command = args.command or "demo"

    if not args.key:
        print("No API key. Set the DATALEAK_API_KEY environment variable or pass --key.")
        return 2
    base = args.url.rstrip("/")

    status, body = call("GET", f"{base}/health")
    if status != 200:
        print(f"API health check failed (HTTP {status}): {body}")
        return 1
    print(f"API at {base} is healthy.\n")

    if command == "one":
        event = {
            "user_id": args.user_id, "username": args.username, "department": args.department,
            "access_type": args.access_type, "records_accessed": args.records,
        }
        if args.query:
            event["query_text"] = args.query
        return 0 if send_event(base, args.key, event) else 1

    print("1. A normal user reads a small number of records:")
    ok1 = send_event(base, args.key, {"user_id": "U1001", "username": "aarav.nair", "department": "Finance",
                                      "access_type": "SELECT Query", "records_accessed": 8})
    print("\n2. Another user reads an unusually large number of records:")
    ok2 = send_event(base, args.key, {"user_id": "U1011", "username": "farhan.ali", "department": "Operations",
                                      "access_type": "Full Table Export", "records_accessed": 3200})
    if ok1 and ok2:
        print("\nOpen the dashboard (Security Alerts, or turn on Live refresh) to see the alert.")
        return 0
    print("\nNot every event was accepted, so nothing new may appear on the dashboard.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
