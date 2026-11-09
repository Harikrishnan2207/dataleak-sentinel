"""Tuning check: what did tuning change, and does it hold up on scenarios it was not tuned on?

Run it with:   python -m sentinel.evaluation_heldout
It writes docs/EVALUATION_HELDOUT.md (deterministic, synthetic data only).

Why this exists. The main evaluation (sentinel/evaluation.py) was run again after the defaults were
changed (anomaly z-score 4.0 to 2.5, cumulative rule 500 rows per 60 minutes to 400 rows per 12 hours)
until it caught every attack, so its headline numbers are in-sample. This report therefore shows:
  1. the previous and current settings side by side on that same data (what tuning bought, in-sample),
  2. both settings on reshaped scenarios and new seeds that no setting was tuned on, and
  3. sweeps that vary one attack parameter across a range, so no single chosen scenario decides the story.
Everything is still written by the same author as the detector, after the current settings were known.
"""
from __future__ import annotations

import argparse
import random
import statistics
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

from .config import BASE_DIR, DEFAULT_SETTINGS, TIME_FORMAT
from .detection import evaluate_logs
from .evaluation import generate_labelled_dataset

# The defaults that shipped before tuning, written out in full so this comparison cannot drift.
PREVIOUS_DEFAULTS: dict[str, float] = {
    "low_max": 20, "medium_max": 100, "repeat_min_records": 50, "repeat_count": 3, "repeat_window_min": 60,
    "freq_count": 10, "freq_window_min": 15, "cumulative_window_min": 60, "cumulative_limit": 500,
    "anomaly_enabled": 1, "anomaly_min_history": 15, "anomaly_min_records": 10, "anomaly_z": 4.0,
}
IN_SAMPLE_SEEDS = list(range(1000, 1030))
HELDOUT_SEEDS = list(range(2000, 2030))
SWEEP_SEED = 5000
NOW = datetime(2026, 3, 1, 12, 0, 0)
HISTORY_DAYS = 14
PROFILES = {"light": (1.1, 0.45, (40, 70)), "typical": (2.0, 0.6, (40, 70)), "heavy": (3.3, 0.7, (30, 60))}
PROFILE_MIX = ["light"] * 15 + ["typical"] * 15 + ["heavy"] * 10
ATTACKS = ["bulk_dump", "repeated_pulls", "rapid_burst", "low_volume_spike", "sub_threshold_drip", "gradual_ramp"]
BENIGN_KINDS = ["ordinary", "legit_export", "legit_burst", "busy_day"]
HELDOUT_NOTES = {
    "bulk_dump": "one pull of 150 to 600 rows (original: 800 to 20,000)",
    "repeated_pulls": "4 pulls of 40 to 120 rows, 8 to 15 minutes apart (original: 5 pulls of 60 to 300)",
    "rapid_burst": "13 queries of 2 to 9 rows, 25 to 70 s apart (original: 18 queries of 3 to 12)",
    "low_volume_spike": "a light user reads 10 to 15 rows (original: 12 to 19)",
    "sub_threshold_drip": "30 queries of 8 to 14 rows, 20 to 45 minutes apart (original: 25 queries of 14 to 20)",
    "gradual_ramp": "20 queries growing to about 50 rows (original: about 90)",
    "legit_export": "a legitimate export of 100 to 250 rows (original: 150 to 400)",
    "busy_day": "three users per organisation run 25 legitimate queries of 10 to 25 rows within about 8 hours (new)",
}


# ---------------------------------------------------------------- held-out data
def _workday_time(rng: random.Random) -> datetime:
    day = rng.randint(0, HISTORY_DAYS - 1)
    t = NOW.replace(hour=0, minute=0, second=0) - timedelta(days=day) + timedelta(
        hours=rng.randint(8, 18), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
    return t - timedelta(days=1) if t > NOW else t


def _attack_start(rng: random.Random) -> datetime:
    return NOW.replace(hour=0, minute=0, second=0) - timedelta(days=rng.randint(1, 3)) + timedelta(
        hours=rng.randint(9, 16), minutes=rng.randint(0, 59))


def generate_heldout_dataset(seed: int) -> pd.DataFrame:
    """Same kinds of users and attacks as the main evaluation, but with reshaped parameters (see HELDOUT_NOTES)."""
    rng = random.Random(seed)
    profiles = PROFILE_MIX[:]
    rng.shuffle(profiles)
    users = [{"user_id": f"H{i:03d}", "username": f"held{i:03d}", "profile": p} for i, p in enumerate(profiles, 1)]
    pool = users[:]
    rng.shuffle(pool)

    def take(profile: str | None = None) -> dict:
        for u in pool:
            if profile is None or u["profile"] == profile:
                pool.remove(u)
                return u
        raise RuntimeError("not enough users")

    events: list[dict] = []
    episodes = [0]

    def add(user, when, rows, label, kind, episode=None):
        events.append({"user_id": user["user_id"], "username": user["username"], "timestamp": when,
                       "records_accessed": max(0, int(rows)), "label": label, "kind": kind, "episode": episode,
                       "profile": user["profile"]})

    for attack in ATTACKS:
        for _ in range(3):
            user = take("light" if attack == "low_volume_spike" else None)
            episodes[0] += 1
            ep, t0 = episodes[0], _attack_start(rng)
            if attack == "bulk_dump":
                add(user, t0, rng.randint(150, 600), 1, attack, ep)
            elif attack == "repeated_pulls":
                t = t0
                for _ in range(4):
                    add(user, t, rng.randint(40, 120), 1, attack, ep)
                    t += timedelta(minutes=rng.uniform(8, 15))
            elif attack == "rapid_burst":
                t = t0
                for _ in range(13):
                    add(user, t, rng.randint(2, 9), 1, attack, ep)
                    t += timedelta(seconds=rng.uniform(25, 70))
            elif attack == "low_volume_spike":
                add(user, t0, rng.randint(10, 15), 1, attack, ep)
            elif attack == "sub_threshold_drip":
                t = t0
                for _ in range(30):
                    add(user, t, rng.randint(8, 14), 1, attack, ep)
                    t += timedelta(minutes=rng.uniform(20, 45))
            else:  # gradual_ramp
                start = max(2.0, 2.718281828 ** PROFILES[user["profile"]][0])
                t = NOW - timedelta(days=7)
                for i in range(20):
                    add(user, t, round(start * (50 / start) ** (i / 19)), 1, attack, ep)
                    t += timedelta(hours=7)

    for _ in range(4):
        user = take("typical")
        for _ in range(2):
            add(user, _workday_time(rng), rng.randint(100, 250), 0, "legit_export")
    for _ in range(6):
        user = take()
        for _ in range(rng.randint(1, 2)):
            t = _workday_time(rng)
            for _ in range(rng.randint(10, 14)):
                add(user, t, rng.randint(1, 6), 0, "legit_burst")
                t += timedelta(seconds=rng.uniform(20, 45))
    for _ in range(3):
        user = take()
        t = _workday_time(rng).replace(hour=9, minute=0)
        for _ in range(25):
            add(user, t, rng.randint(10, 25), 0, "busy_day")
            t += timedelta(minutes=rng.uniform(8, 25))
    for user in users:
        mu, sigma, (low, high) = PROFILES[user["profile"]]
        for _ in range(rng.randint(low, high)):
            add(user, _workday_time(rng), round(rng.lognormvariate(mu, sigma)) or 1, 0, "ordinary")

    df = pd.DataFrame(events).sort_values(["timestamp", "user_id"], kind="stable").reset_index(drop=True)
    df["log_id"] = range(1, len(df) + 1)
    df["timestamp"] = df["timestamp"].dt.strftime(TIME_FORMAT)
    return df


# ---------------------------------------------------------------- scoring + metrics
def score(df: pd.DataFrame, settings: dict) -> pd.DataFrame:
    scored = df.merge(evaluate_logs(df, dict(settings)), on="log_id")
    scored["flagged"] = scored["risk_level"].isin(["Medium", "High"])
    return scored


def ratio(num: float, den: float):
    return num / den if den else None


def pct(value, digits: int = 0) -> str:
    return "n/a" if value is None else f"{100 * value:.{digits}f}%"


def episode_stats(scored: pd.DataFrame) -> list[dict]:
    """Per attack episode: detected?, how many events, and what share of its rows was already read when the first alert fired."""
    out = []
    for _, grp in scored[scored["episode"].notna()].groupby("episode"):
        grp = grp.sort_values(["timestamp", "log_id"])
        flags, rows = list(grp["flagged"]), [int(r) for r in grp["records_accessed"]]
        first = flags.index(True) if any(flags) else None
        read = sum(rows[: first + 1]) if first is not None else sum(rows)
        out.append({"kind": grp["kind"].iloc[0], "events": len(rows), "detected": first is not None,
                    "events_before_first_alert": first, "share_read": ratio(read, sum(rows))})
    return out


def run_family(dataset_fn, seeds: list[int], settings: dict) -> dict:
    episodes, benign, conf = [], defaultdict(lambda: [0, 0]), defaultdict(int)
    for seed in seeds:
        scored = score(dataset_fn(seed), settings)
        episodes.extend(episode_stats(scored))
        pos = scored["label"] == 1
        for k, mask in (("tp", pos & scored["flagged"]), ("fp", ~pos & scored["flagged"]),
                        ("fn", pos & ~scored["flagged"]), ("tn", ~pos & ~scored["flagged"])):
            conf[k] += int(mask.sum())
        for kind, grp in scored[scored["label"] == 0].groupby("kind"):
            benign[kind][0] += int(grp["flagged"].sum())
            benign[kind][1] += len(grp)
    return {"episodes": episodes, "benign": dict(benign), "confusion": dict(conf)}


def detection(eps: list[dict], kind: str | None = None):
    sel = [e for e in eps if kind is None or e["kind"] == kind]
    return sum(e["detected"] for e in sel), len(sel)


def median_share(eps: list[dict], kind: str):
    shares = [e["share_read"] for e in eps if e["kind"] == kind and e["events"] > 1]
    return statistics.median(shares) if shares else None


# ---------------------------------------------------------------- sweeps
def _history(rng: random.Random, profile: str, user_id: str) -> list[dict]:
    mu, sigma, (low, high) = PROFILES[profile]
    return [{"user_id": user_id, "timestamp": _workday_time(rng),
             "records_accessed": round(rng.lognormvariate(mu, sigma)) or 1, "attack": 0}
            for _ in range(rng.randint(low, high))]


def _score_user(rows: list[dict], settings: dict) -> pd.DataFrame:
    df = pd.DataFrame(rows).sort_values("timestamp", kind="stable").reset_index(drop=True)
    df["log_id"] = range(1, len(df) + 1)
    df["timestamp"] = df["timestamp"].dt.strftime(TIME_FORMAT)
    res = evaluate_logs(df, dict(settings))
    out = df.merge(res, on="log_id")
    out["flagged"] = out["risk_level"].isin(["Medium", "High"])
    return out


def sweep_spike(sizes: list[int], trials: int, settings: dict) -> dict[int, float]:
    """A light user (typical size about 3 rows) suddenly reads `size` rows once."""
    out = {}
    for size in sizes:
        hits = 0
        for i in range(trials):
            rng = random.Random(SWEEP_SEED + 1000 * size + i)
            rows = _history(rng, "light", "U")
            rows.append({"user_id": "U", "timestamp": _attack_start(rng), "records_accessed": size, "attack": 1})
            scored = _score_user(rows, settings)
            hits += bool(scored[scored["attack"] == 1]["flagged"].any())
        out[size] = hits / trials
    return out


def sweep_drip(sizes: list[int], trials: int, settings: dict, queries: int = 30) -> dict[int, dict]:
    """`queries` queries of about `size` rows, 20 to 45 minutes apart, by a randomly chosen user."""
    out = {}
    for size in sizes:
        hits, shares = 0, []
        for i in range(trials):
            rng = random.Random(SWEEP_SEED + 7000 + 1000 * size + i)
            profile = rng.choice(PROFILE_MIX)
            rows = _history(rng, profile, "U")
            t = _attack_start(rng)
            for _ in range(queries):
                rows.append({"user_id": "U", "timestamp": t, "records_accessed": rng.randint(max(1, size - 1), size + 1),
                             "attack": 1})
                t += timedelta(minutes=rng.uniform(20, 45))
            scored = _score_user(rows, settings)
            drip = scored[scored["attack"] == 1].reset_index(drop=True)
            flags, rs = list(drip["flagged"]), [int(r) for r in drip["records_accessed"]]
            first = flags.index(True) if any(flags) else None
            hits += first is not None
            shares.append(sum(rs[: first + 1]) / sum(rs) if first is not None else 1.0)
        out[size] = {"detected": hits / trials, "share_read": statistics.median(shares), "total": queries * size}
    return out


def follow_on_example(settings: dict) -> list[dict]:
    """One legitimate 420-row export followed by tiny lookups over the next hours."""
    t0 = datetime(2026, 3, 2, 9, 0, 0)
    rows = [{"log_id": 1, "user_id": "U1", "timestamp": t0.strftime(TIME_FORMAT), "records_accessed": 420}]
    for i in range(2, 9):
        rows.append({"log_id": i, "user_id": "U1", "records_accessed": 3,
                     "timestamp": (t0 + timedelta(hours=1.7 * (i - 1))).strftime(TIME_FORMAT)})
    res = evaluate_logs(pd.DataFrame(rows), dict(settings)).set_index("log_id")
    return [{"time": r["timestamp"][11:16], "rows": r["records_accessed"], "level": res.loc[r["log_id"], "risk_level"],
             "score": int(res.loc[r["log_id"], "risk_score"])} for r in rows]


# ---------------------------------------------------------------- orchestration + report
def build_results(in_seeds=None, held_seeds=None, spike_trials: int = 200, drip_trials: int = 100) -> dict:
    in_seeds, held_seeds = in_seeds or IN_SAMPLE_SEEDS, held_seeds or HELDOUT_SEEDS
    current = dict(DEFAULT_SETTINGS)
    variants = {"previous": PREVIOUS_DEFAULTS, "current": current}
    spike_sizes, drip_sizes = [8, 10, 12, 14, 16, 18, 20], [4, 6, 8, 10, 12, 14, 16, 18]
    return {
        "in_seeds": in_seeds, "held_seeds": held_seeds, "settings": variants,
        "in_sample": {n: run_family(generate_labelled_dataset, in_seeds, s) for n, s in variants.items()},
        "held_out": {n: run_family(generate_heldout_dataset, held_seeds, s) for n, s in variants.items()},
        "spike": {n: sweep_spike(spike_sizes, spike_trials, s) for n, s in variants.items()},
        "drip": {n: sweep_drip(drip_sizes, drip_trials, s) for n, s in variants.items()},
        "spike_trials": spike_trials, "drip_trials": drip_trials,
        "follow_on": follow_on_example(current),
    }


def _first_at_least(curve: dict, key=lambda v: v, level: float = 0.5):
    for size in sorted(curve):
        if key(curve[size]) >= level:
            return size
    return None


def render_report(res: dict) -> str:
    L: list[str] = []
    w = L.append
    prev, cur = res["settings"]["previous"], res["settings"]["current"]
    w("# Tuning check: before and after, on scenarios the tuning never saw\n")
    w("Generated by `python -m sentinel.evaluation_heldout`; deterministic and synthetic. **Read this next to "
      "`EVALUATION.md`.** The main report was re-run after the defaults were changed until every attack was caught, so "
      "its headline numbers are in-sample. This report shows what the tuning changed, how the result holds up on "
      "reshaped scenarios, and where the thresholds actually sit.\n")
    w("## Settings compared\n")
    w("| Setting | Previous defaults | Current defaults |")
    w("|---|---|---|")
    for key in sorted(prev):
        if prev[key] != cur.get(key):
            w(f"| `{key}` | {prev[key]:g} | {cur[key]:g} |")
    w("\nAll other settings are identical. \"Previous\" is written out in full in the code so it cannot drift.\n")

    for title, fam, seeds, note in (
        ("A. Original scenarios (in-sample: the tuning was done against this data)", "in_sample", res["in_seeds"],
         "Same data as `EVALUATION.md`."),
        ("B. Reshaped scenarios, new seeds (not used for tuning)", "held_out", res["held_seeds"],
         "Same kinds of attacks with different sizes, speeds and counts, plus a new legitimate case (`busy_day`)."),
    ):
        w(f"## {title}\n")
        w(f"{len(seeds)} synthetic organisations (seeds {seeds[0]} to {seeds[-1]}). {note}\n")
        w("| Attack | Episodes | Previous: detected | Current: detected | Current: share of the attacker's rows already read when the first alert fired |")
        w("|---|---|---|---|---|")
        for a in ATTACKS:
            dp, n = detection(res[fam]["previous"]["episodes"], a)
            dc, _ = detection(res[fam]["current"]["episodes"], a)
            share = median_share(res[fam]["current"]["episodes"], a)
            w(f"| `{a}` | {n} | {dp}/{n} ({pct(ratio(dp, n))}) | {dc}/{n} ({pct(ratio(dc, n))}) | "
              f"{'one event' if share is None else pct(share)} |")
        dp, n = detection(res[fam]["previous"]["episodes"])
        dc, _ = detection(res[fam]["current"]["episodes"])
        w(f"| **All attacks** | {n} | **{dp}/{n} ({pct(ratio(dp, n))})** | **{dc}/{n} ({pct(ratio(dc, n))})** | |")
        w("\nFalse alerts on benign events:\n")
        w("| Benign activity | Events | Previous | Current |")
        w("|---|---|---|---|")
        for kind in BENIGN_KINDS:
            if kind not in res[fam]["current"]["benign"]:
                continue
            fc, total = res[fam]["current"]["benign"][kind]
            fp_ = res[fam]["previous"]["benign"][kind][0]
            w(f"| `{kind}` | {total:,} | {fp_:,} ({pct(ratio(fp_, total), 1)}) | {fc:,} ({pct(ratio(fc, total), 1)}) |")
        for name in ("previous", "current"):
            c = res[fam][name]["confusion"]
            w(f"\n- {name.capitalize()}: precision {pct(ratio(c['tp'], c['tp'] + c['fp']), 1)}, "
              f"recall {pct(ratio(c['tp'], c['tp'] + c['fn']), 1)}, "
              f"false alerts {pct(ratio(c['fp'], c['fp'] + c['tn']), 2)} of benign events.")
        w("")
    w("What changed in the reshaped scenarios (B):\n")
    for kind, note in HELDOUT_NOTES.items():
        w(f"- `{kind}`: {note}.")

    w("\n## C. Sweeps: vary one attack parameter and watch detection\n")
    w(f"No single scenario is chosen here; the whole range is shown. {res['spike_trials']} trials per row for the "
      f"spike sweep and {res['drip_trials']} per row for the drip sweep, each on a freshly generated user with 14 days of history.\n")
    w("**Spike:** a light user (typical size about 3 rows) reads `size` rows once. Share of trials where an alert fired:\n")
    w("| Rows read | Previous settings | Current settings |")
    w("|---|---|---|")
    for size in sorted(res["spike"]["current"]):
        w(f"| {size} | {pct(res['spike']['previous'][size])} | {pct(res['spike']['current'][size])} |")
    w("\n**Drip:** 30 queries of about `size` rows each (each query varies by one row either way), 20 to 45 minutes "
      "apart, by a randomly chosen user. Sizes stop at 18 because 20 or more rows per query would already trip the plain "
      "20-row volume limit:\n")
    w("| Rows per query | Total rows | Previous: detected | Current: detected | Current: share of total rows read when first alert fired (median) |")
    w("|---|---|---|---|---|")
    for size in sorted(res["drip"]["current"]):
        p, c = res["drip"]["previous"][size], res["drip"]["current"][size]
        w(f"| {size} | {c['total']} | {pct(p['detected'])} | {pct(c['detected'])} | {pct(c['share_read'])} |")

    w("\n## D. A side effect of the 12-hour cumulative rule: follow-on alerts\n")
    w("One legitimate 420-row export, then tiny lookups over the next hours (current settings):\n")
    w("| Time | Rows | Level | Score |")
    w("|---|---|---|---|")
    for r in res["follow_on"]:
        w(f"| {r['time']} | {r['rows']} | {r['level']} | {r['score']} |")
    storm = sum(1 for r in res["follow_on"][1:] if r["level"] != "Low")
    w(f"\nThe export itself alerts, and so does each of the next {storm} three-row lookups, because the running total stays "
      "above the limit for 12 hours. One incident becomes many alerts.\n")

    w("## What this shows\n")
    ia = detection(res["in_sample"]["current"]["episodes"])
    ib = detection(res["held_out"]["current"]["episodes"])
    pa, pb = (detection(res["in_sample"]["previous"]["episodes"]), detection(res["held_out"]["previous"]["episodes"]))
    ra, rb = ratio(*ia), ratio(*ib)
    w(f"- **In-sample vs reshaped:** the current settings detect {pct(ra)} of attack episodes on the data they were tuned "
      f"on, but {pct(rb)} on reshaped scenarios, a gap of {100 * (ra - rb):.0f} points. The previous settings detect "
      f"{pct(ratio(*pa))} and {pct(ratio(*pb))}. Treat the in-sample figure as an upper bound, not as accuracy.")
    for a in ATTACKS:
        dc, n = detection(res["held_out"]["current"]["episodes"], a)
        di, ni = detection(res["in_sample"]["current"]["episodes"], a)
        if dc / n < 0.9:
            w(f"- **Weakness:** `{a}` is detected in {pct(di / ni)} of original episodes but only {pct(dc / n)} of reshaped ones.")
    spike_cur = _first_at_least(res["spike"]["current"])
    spike_prev = _first_at_least(res["spike"]["previous"])
    best_prev = max(res["spike"]["previous"].values())
    prev_text = (f"from {spike_prev} rows with the previous ones" if spike_prev
                 else f"never within the tested range with the previous ones (best {pct(best_prev)})")
    cur_text = f"from {spike_cur} rows" if spike_cur else "never within the tested range"
    w(f"- **Spike sweep:** an alert fires in at least half the trials {cur_text} with the current settings, {prev_text}.")
    drip_cur = _first_at_least(res["drip"]["current"], key=lambda v: v["detected"])
    if drip_cur:
        below = [1 - v["detected"] for s, v in res["drip"]["current"].items() if s < drip_cur]
        low_text = (f" At smaller sizes, {pct(min(below))} to {pct(max(below))} of trials were never alerted at all."
                    if below else "")
        w(f"- **Drip sweep:** detection reaches half the trials at about {drip_cur} rows per query (about {30 * drip_cur} "
          f"rows in total, against the {cur['cumulative_limit']:g}-row cumulative limit).{low_text} Even above the "
          "limit the alert comes late (see the share-read column).")
    else:
        w("- **Drip sweep:** no tested drip size reached half of trials with the current settings.")
    bi, bh = res["in_sample"], res["held_out"]
    if "busy_day" in bh["current"]["benign"]:
        fc, total = bh["current"]["benign"]["busy_day"]
        fp_ = bh["previous"]["benign"]["busy_day"][0]
        w(f"- **Cost:** a legitimate busy working day is flagged {pct(ratio(fp_, total))} of the time with the previous "
          f"settings and {pct(ratio(fc, total))} with the current ones.")
    w(f"- **Alert fatigue:** after one large access every later access for 12 hours is also flagged "
      f"({storm} follow-on alerts in the example above).")

    w("\n## Limits of this report\n")
    w("- I wrote the reshaped scenarios and sweeps after the current settings were known, by the same author as the "
      "detector. The sweeps are the fairer view because they show the whole range, but the shapes (30 queries, 20 to 45 "
      "minutes apart, light users) are still my assumptions.")
    w("- Real attackers adapt. An attacker who knows a fixed limit stays under it, and the sweeps show where that "
      "limit sits.")
    w("- Nothing here measures performance on real users or real attacks.")
    w("- Reproduce with `python -m sentinel.evaluation_heldout` (under a minute). Changing the code, the seeds "
      "or the settings changes the numbers.")
    return "\n".join(L) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Before/after and held-out check of the detection settings.")
    parser.add_argument("--out", default=str(BASE_DIR / "docs" / "EVALUATION_HELDOUT.md"))
    parser.add_argument("--print", action="store_true", help="print the report instead of writing a file")
    args = parser.parse_args()
    report = render_report(build_results())
    if args.print:
        print(report)
        return
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")
    print(f"Report written to {out}")


if __name__ == "__main__":
    main()
