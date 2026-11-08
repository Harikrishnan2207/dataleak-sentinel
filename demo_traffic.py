"""Post a short, synthetic three-act story to the DataLeak Sentinel API.

Start the API with DATALEAK_API_KEY set, then run:
    python demo_traffic.py
    python demo_traffic.py --dry-run
    python demo_traffic.py --delay 6.5
"""
from __future__ import annotations

import argparse
import json
import math
import os
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta

import pandas as pd

from sentinel.config import DEFAULT_SETTINGS
from sentinel.detection import evaluate_logs

DEFAULT_URL = "http://127.0.0.1:8000"
REPEATED_ACCESS_RECORDS = (6, 8, 10, 7, 11, 9, 12, 6, 8, 10)
SIMULATION_PREFIX = "[SIMULATED SYNTHETIC TRAFFIC]"


def build_event_plan(run_id: str) -> list[dict]:
    """Build the same events for a given run id, with user ids unique across runs."""
    if not run_id.isascii() or not run_id.isalnum() or not 1 <= len(run_id) <= 12:
        raise ValueError("run_id must contain 1-12 ASCII letters or digits.")

    normal_users = (
        ("Finance", (8, 12)),
        ("Operations", (5,)),
        ("Sales", (15, 7)),
        ("Human Resources", (10,)),
        ("IT", (6, 9)),
        ("Legal", (13,)),
    )
    events = []
    for user_number, (department, accesses) in enumerate(normal_users, start=1):
        user_id = f"D{run_id}N{user_number:02d}"
        username = f"demo-normal{user_number:02d}-{run_id}"
        for records in accesses:
            events.append({
                "act": "Normal day",
                "user": username,
                "payload": {
                    "user_id": user_id,
                    "username": username,
                    "department": department,
                    "access_type": "SELECT Query",
                    "records_accessed": records,
                },
            })

    repeated_id = f"D{run_id}REPEAT"
    repeated_user = f"demo-repeat-{run_id}"
    for records in REPEATED_ACCESS_RECORDS:
        events.append({
            "act": "Repeated small accesses",
            "user": repeated_user,
            "payload": {
                "user_id": repeated_id,
                "username": repeated_user,
                "department": "Operations",
                "access_type": "SELECT Query",
                "records_accessed": records,
            },
        })

    bulk_user = f"demo-bulk-{run_id}"
    events.append({
        "act": "Bulk dump",
        "user": bulk_user,
        "payload": {
            "user_id": f"D{run_id}BULK",
            "username": bulk_user,
            "department": "Operations",
            "access_type": "Full Table Export",
            "records_accessed": 3200,
        },
    })
    return events


def score_plan(events: list[dict], delay: float = 1.5) -> dict[int, dict]:
    """Score the plan with production rules and timestamps spaced by the live delay."""
    start = datetime(2026, 1, 1, 12, 0, 0)
    rows = [
        (
            index,
            event["payload"]["user_id"],
            (start + timedelta(seconds=delay * (index - 1))).strftime("%Y-%m-%d %H:%M:%S"),
            event["payload"]["records_accessed"],
        )
        for index, event in enumerate(events, start=1)
    ]
    logs = pd.DataFrame(rows, columns=["log_id", "user_id", "timestamp", "records_accessed"])
    results = evaluate_logs(logs, dict(DEFAULT_SETTINGS))
    return results.set_index("log_id").to_dict("index")


def explain(detail) -> str:
    if isinstance(detail, list):
        return "; ".join(
            f"{'.'.join(str(part) for part in item.get('loc', [])[1:])}: {item.get('msg')}"
            for item in detail
        )
    return str(detail)


def post_event(base_url: str, api_key: str, payload: dict) -> tuple[int, object]:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url}/events",
        data=data,
        method="POST",
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        try:
            body = json.loads(error.read().decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            body = {"detail": error.reason}
        return error.code, body


def print_line(message: str) -> None:
    print(f"{SIMULATION_PREFIX} {message}")


def print_summary(rows: list[tuple[str, int, object, object, object]]) -> None:
    print_line("Final summary (online scores and alert ids are API responses):")
    print_line(f"{'User':<28} {'Records':>7} {'Score':>5} {'Level':<8} {'Alert ID':>8}")
    for user, records, score, level, alert_id in rows:
        print_line(f"{user:<28} {records:>7} {score:>5} {level:<8} {alert_id:>8}")


def run_dry_run(events: list[dict], delay: float) -> int:
    results = score_plan(events, delay)
    print_line("DRY RUN - planned events and offline scores; no network calls.")
    current_act = None
    summary = []
    repeated_event_number = 0
    escalation_reported = False
    for index, event in enumerate(events, start=1):
        if event["act"] != current_act:
            current_act = event["act"]
            print_line(f"ACT: {current_act}")
        result = results[index]
        reason = result["reason"]
        alert = result["risk_level"] != "Low"
        payload = event["payload"]
        if event["act"] == "Repeated small accesses":
            repeated_event_number += 1
            if "Unusual access frequency" in reason and not escalation_reported:
                escalation_reported = True
                print_line(
                    f"Behavioral escalation first triggers on event {repeated_event_number}: "
                    f"score {result['risk_score']}, {result['risk_level']}; {reason}"
                )
        alert_text = "offline alert predicted; no API alert id" if alert else "no alert"
        print_line(
            f"{event['act']} | {event['user']} | {payload['records_accessed']} records | "
            f"score {result['risk_score']} | {result['risk_level']} | {alert_text} | {reason}"
        )
        summary.append((
            event["user"], payload["records_accessed"], result["risk_score"],
            result["risk_level"], "not assigned",
        ))
    print_summary(summary)
    return 0


def run_online(events: list[dict], base_url: str, api_key: str, delay: float) -> int:
    print_line("Posting synthetic events to the configured API.")
    current_act = None
    summary = []
    repeated_event_number = 0
    escalation_reported = False
    for index, event in enumerate(events):
        if index:
            time.sleep(delay)
        if event["act"] != current_act:
            current_act = event["act"]
            print_line(f"ACT: {current_act}")
        try:
            status, body = post_event(base_url, api_key, event["payload"])
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            reason = getattr(error, "reason", error)
            print_line(f"ERROR: cannot reach API at {base_url}: {reason}")
            print_summary(summary)
            return 1
        except (UnicodeDecodeError, json.JSONDecodeError):
            print_line("ERROR: API returned a response that was not valid JSON.")
            print_summary(summary)
            return 1

        if status == 401:
            print_line("ERROR: HTTP 401 - DATALEAK_API_KEY was rejected or missing.")
            print_summary(summary)
            return 1
        if status == 422:
            detail = body.get("detail", body) if isinstance(body, dict) else body
            print_line(f"ERROR: HTTP 422 - event rejected: {explain(detail)}")
            print_summary(summary)
            return 1
        if status != 201 or not isinstance(body, dict):
            print_line(f"ERROR: API returned HTTP {status}: {body}")
            print_summary(summary)
            return 1

        required = ("risk_score", "risk_level", "reason", "alert_id")
        if any(field not in body for field in required):
            print_line("ERROR: API response is missing expected scoring fields.")
            print_summary(summary)
            return 1
        alert_id = body["alert_id"]
        alert_text = f"ALERT #{alert_id}" if alert_id is not None else "no alert"
        print_line(
            f"{event['act']} | {event['user']} | {event['payload']['records_accessed']} records | "
            f"score {body['risk_score']} | {body['risk_level']} | {alert_text} | {body['reason']}"
        )
        if event["act"] == "Repeated small accesses":
            repeated_event_number += 1
            if "Unusual access frequency" in body["reason"] and not escalation_reported:
                escalation_reported = True
                print_line(
                    f"Behavioral escalation first returned on event {repeated_event_number}: "
                    f"score {body['risk_score']}, {body['risk_level']}; {body['reason']}"
                )
        summary.append((
            event["user"], event["payload"]["records_accessed"], body["risk_score"],
            body["risk_level"], alert_id if alert_id is not None else "not assigned",
        ))
    print_summary(summary)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL, help=f"API base URL (default: {DEFAULT_URL})")
    parser.add_argument("--delay", type=float, default=1.5, help="seconds between events (default: 1.5)")
    parser.add_argument("--dry-run", action="store_true", help="show the plan and offline scores without networking")
    args = parser.parse_args(argv)
    if not math.isfinite(args.delay) or args.delay < 0:
        parser.error("--delay must be a finite, non-negative number.")

    run_id = uuid.uuid4().hex[:8]
    events = build_event_plan(run_id)
    if args.dry_run:
        return run_dry_run(events, args.delay)

    api_key = os.environ.get("DATALEAK_API_KEY")
    if not api_key:
        print_line("ERROR: set DATALEAK_API_KEY before running the live demo.")
        return 2
    return run_online(events, args.url.rstrip("/"), api_key, args.delay)


if __name__ == "__main__":
    raise SystemExit(main())
