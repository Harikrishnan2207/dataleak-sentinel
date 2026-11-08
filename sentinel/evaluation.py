"""Evaluation of the detection engine on labelled synthetic scenarios.

Run it with:   python -m sentinel.evaluation
It writes docs/EVALUATION.md. The numbers are deterministic: the same code and seeds give the
same report. Everything here is synthetic. It measures how the rules behave on data the author
designed, not how they would behave against real users or real attackers.

Design choices that keep the exercise honest:
  * This benchmark is deterministic and separate from the demo generator, but the current
    detector defaults were adjusted after inspecting results on this benchmark. It is now a
    development/regression set, not an independent holdout.
  * Ground truth comes from how each event was generated (attack episode or not), not from the detector.
  * Benign data includes legitimate but unusual activity (large exports, bursts of lookups) that
    should cause false alerts, and attacks built to slip under the thresholds that should cause misses.
  * Three configurations are compared so each part of the engine can be judged by what it adds.
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

NOW = datetime(2026, 3, 1, 12, 0, 0)
HISTORY_DAYS = 14
FIRST_SEED = 1000
DEFAULT_SEEDS = 30
EPISODES_PER_ATTACK = 3

# profile -> (log-normal mu, sigma, (min, max) ordinary events over the period). Median rows = e**mu.
PROFILES = {"light": (1.1, 0.45, (40, 70)), "typical": (2.0, 0.6, (40, 70)), "heavy": (3.3, 0.7, (30, 60))}
PROFILE_MIX = ["light"] * 15 + ["typical"] * 15 + ["heavy"] * 10
ATTACKS = ["bulk_dump", "repeated_pulls", "rapid_burst", "low_volume_spike", "sub_threshold_drip", "gradual_ramp"]
ATTACK_NOTES = {
    "bulk_dump": "one huge pull (800 to 20,000 rows)",
    "repeated_pulls": "5 pulls of 60 to 300 rows, 6 to 12 minutes apart",
    "rapid_burst": "18 small queries (3 to 12 rows), 20 to 60 s apart",
    "low_volume_spike": "a steady light user suddenly reads 12 to 19 rows (inside the Low band)",
    "sub_threshold_drip": "25 queries of 14 to 20 rows, 15 to 40 minutes apart (built to stay under every threshold)",
    "gradual_ramp": "20 queries over 5.5 days growing from the user's normal size to about 90 rows",
}
BENIGN_KINDS = ["ordinary", "legit_export", "legit_burst"]
BENIGN_NOTES = {
    "ordinary": "everyday activity with each user's own typical size",
    "legit_export": "a legitimate weekly export of 150 to 400 rows",
    "legit_burst": "a legitimate burst of 10 to 14 small lookups within about 8 minutes",
}
CONFIGS = {
    "thresholds_only": (
        "Volume thresholds only",
        {"repeat_count": 10**9, "freq_count": 10**9, "cumulative_limit": 10**12, "anomaly_enabled": 0},
    ),
    "rules_no_anomaly": ("Volume + behaviour rules", {"anomaly_enabled": 0}),
    "full_default": ("Full engine (defaults)", {}),
}


# ---------------------------------------------------------------- data generation
def _workday_time(rng: random.Random) -> datetime:
    day = rng.randint(0, HISTORY_DAYS - 1)
    t = NOW.replace(hour=0, minute=0, second=0) - timedelta(days=day) + timedelta(
        hours=rng.randint(8, 18), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
    return t - timedelta(days=1) if t > NOW else t


def _attack_start(rng: random.Random) -> datetime:
    return NOW.replace(hour=0, minute=0, second=0) - timedelta(days=rng.randint(1, 3)) + timedelta(
        hours=rng.randint(9, 16), minutes=rng.randint(0, 59))


def generate_labelled_dataset(seed: int) -> pd.DataFrame:
    """One synthetic organisation: 40 users, 14 days of activity, attack episodes and benign oddities."""
    rng = random.Random(seed)
    profiles = PROFILE_MIX[:]
    rng.shuffle(profiles)
    users = [{"user_id": f"E{i:03d}", "username": f"emp{i:03d}", "profile": p} for i, p in enumerate(profiles, 1)]
    pool = users[:]
    rng.shuffle(pool)

    def take(profile: str | None = None) -> dict:
        for u in pool:
            if profile is None or u["profile"] == profile:
                pool.remove(u)
                return u
        raise RuntimeError("not enough users")

    events: list[dict] = []
    episode_counter = [0]

    def add(user, when, rows, label, kind, episode=None):
        events.append({"user_id": user["user_id"], "username": user["username"], "timestamp": when,
                       "records_accessed": max(0, int(rows)), "label": label, "kind": kind, "episode": episode,
                       "profile": user["profile"]})

    # Attack episodes (each on its own user, who also has ordinary history).
    for attack in ATTACKS:
        for _ in range(EPISODES_PER_ATTACK):
            user = take("light" if attack == "low_volume_spike" else None)
            episode_counter[0] += 1
            ep = episode_counter[0]
            t0 = _attack_start(rng)
            if attack == "bulk_dump":
                add(user, t0, rng.randint(800, 20000), 1, attack, ep)
            elif attack == "repeated_pulls":
                t = t0
                for _ in range(5):
                    add(user, t, rng.randint(60, 300), 1, attack, ep)
                    t += timedelta(minutes=rng.uniform(6, 12))
            elif attack == "rapid_burst":
                t = t0
                for _ in range(18):
                    add(user, t, rng.randint(3, 12), 1, attack, ep)
                    t += timedelta(seconds=rng.uniform(20, 60))
            elif attack == "low_volume_spike":
                add(user, t0, rng.randint(12, 19), 1, attack, ep)
            elif attack == "sub_threshold_drip":
                t = t0
                for _ in range(25):
                    add(user, t, rng.randint(14, 20), 1, attack, ep)
                    t += timedelta(minutes=rng.uniform(15, 40))
            elif attack == "gradual_ramp":
                start = max(2.0, 2.718281828 ** PROFILES[user["profile"]][0])
                t = NOW - timedelta(days=7)
                for i in range(20):
                    add(user, t, round(start * (90 / start) ** (i / 19)), 1, attack, ep)
                    t += timedelta(hours=7)

    # Benign oddities: legitimate activity that looks unusual.
    for _ in range(4):
        user = take("typical")
        for _ in range(2):
            add(user, _workday_time(rng), rng.randint(150, 400), 0, "legit_export")
    for _ in range(6):
        user = take()
        for _ in range(rng.randint(1, 2)):
            t = _workday_time(rng)
            for _ in range(rng.randint(10, 14)):
                add(user, t, rng.randint(1, 6), 0, "legit_burst")
                t += timedelta(seconds=rng.uniform(20, 45))

    # Ordinary activity for everyone.
    for user in users:
        mu, sigma, (low, high) = PROFILES[user["profile"]]
        for _ in range(rng.randint(low, high)):
            add(user, _workday_time(rng), round(rng.lognormvariate(mu, sigma)) or 1, 0, "ordinary")

    df = pd.DataFrame(events).sort_values(["timestamp", "user_id"], kind="stable").reset_index(drop=True)
    df["log_id"] = range(1, len(df) + 1)
    df["timestamp"] = df["timestamp"].dt.strftime(TIME_FORMAT)
    return df


# ---------------------------------------------------------------- scoring + metrics
def score_dataset(df: pd.DataFrame, overrides: dict) -> pd.DataFrame:
    cfg = {**DEFAULT_SETTINGS, **overrides}
    scored = df.merge(evaluate_logs(df, cfg), on="log_id")
    scored["flagged"] = scored["risk_level"].isin(["Medium", "High"])
    return scored


def ratio(num: float, den: float):
    return num / den if den else None


def pct(value, digits: int = 1) -> str:
    return "n/a" if value is None else f"{100 * value:.{digits}f}%"


def confusion(scored: pd.DataFrame) -> dict:
    pos, flagged = scored["label"] == 1, scored["flagged"]
    return {"tp": int((pos & flagged).sum()), "fp": int((~pos & flagged).sum()),
            "fn": int((pos & ~flagged).sum()), "tn": int((~pos & ~flagged).sum())}


def episode_outcomes(scored: pd.DataFrame) -> list[dict]:
    """For every attack episode: was at least one of its events flagged, and after how many events?"""
    out = []
    for ep, grp in scored[scored["episode"].notna()].groupby("episode"):
        grp = grp.sort_values(["timestamp", "log_id"])
        flags = list(grp["flagged"])
        out.append({"kind": grp["kind"].iloc[0], "events": len(grp), "detected": any(flags),
                    "events_before_first_alert": flags.index(True) if any(flags) else None,
                    "events_flagged": sum(flags)})
    return out


def run_evaluation(seeds: list[int]) -> dict:
    results = {name: {"confusion": defaultdict(int), "benign": defaultdict(lambda: [0, 0]),
                      "by_profile": defaultdict(lambda: [0, 0]), "episodes": [], "per_seed": []} for name in CONFIGS}
    for seed in seeds:
        data = generate_labelled_dataset(seed)
        for name, (_, overrides) in CONFIGS.items():
            scored = score_dataset(data, overrides)
            c = confusion(scored)
            for k, v in c.items():
                results[name]["confusion"][k] += v
            for kind in BENIGN_KINDS:
                part = scored[scored["kind"] == kind]
                results[name]["benign"][kind][0] += int(part["flagged"].sum())
                results[name]["benign"][kind][1] += len(part)
            for profile in PROFILES:
                part = scored[(scored["kind"] == "ordinary") & (scored["profile"] == profile)]
                results[name]["by_profile"][profile][0] += int(part["flagged"].sum())
                results[name]["by_profile"][profile][1] += len(part)
            eps = episode_outcomes(scored)
            results[name]["episodes"].extend(eps)
            results[name]["per_seed"].append({
                "seed": seed, "episode_recall": ratio(sum(e["detected"] for e in eps), len(eps)),
                "benign_fpr": ratio(c["fp"], c["fp"] + c["tn"]),
                "event_recall": ratio(c["tp"], c["tp"] + c["fn"]), "precision": ratio(c["tp"], c["tp"] + c["fp"])})
    return {"seeds": seeds, "results": results, "dataset": generate_labelled_dataset(seeds[0])}


# ---------------------------------------------------------------- report
def _spread(values: list) -> str:
    vals = [v for v in values if v is not None]
    return "n/a" if not vals else f"{pct(min(vals))} / {pct(statistics.median(vals))} / {pct(max(vals))}"


def render_report(data: dict) -> str:
    seeds, res = data["seeds"], data["results"]
    sample = data["dataset"]
    n_events = len(sample)
    lines: list[str] = []
    w = lines.append
    w("# Detection evaluation on labelled synthetic scenarios\n")
    w("Generated by `python -m sentinel.evaluation`. The numbers are deterministic: the same code and seeds "
      "reproduce this file exactly. **Everything here is synthetic.** It measures how the rules behave on data "
      "designed by the author, not how they would perform against real users or real attackers.\n")
    w("## How the test works\n")
    w(f"- **{len(seeds)} synthetic organisations** (seeds {seeds[0]} to {seeds[-1]}). Each has 40 users in three "
      f"profiles (15 light readers with a typical size near 3 rows, 15 typical near 7, 10 heavy analysts near 27) and "
      f"{HISTORY_DAYS} days of ordinary activity (about {n_events:,} events per organisation).")
    w(f"- **Attack episodes** ({EPISODES_PER_ATTACK} per type per organisation, each on a different user who also has "
      f"normal history):")
    for a in ATTACKS:
        w(f"  - `{a}`: {ATTACK_NOTES[a]}.")
    w("- **Benign activity**, including deliberately awkward cases that should cause false alerts:")
    for k in BENIGN_KINDS:
        w(f"  - `{k}`: {BENIGN_NOTES[k]}.")
    w("- **Ground truth** comes from how each event was generated. An event is *malicious* if it belongs to an attack "
      "episode, and *benign* otherwise. The detector never sees these labels.")
    w("- **A flagged event** is one scored Medium or High (the system raises an alert for these). An attack episode is "
      "**detected** if at least one of its events is flagged.")
    w("- **Three configurations** show what each layer adds: volume thresholds only; volume plus the behaviour rules "
      "(repeated access, frequency, cumulative volume); and the full engine with the per-user anomaly rule, using the "
      "shipped default settings.")
    w("- **Development tuning:** the current defaults (12-hour cumulative window, 400-record cumulative limit, "
      "and robust anomaly z-score 2.5) were selected after inspecting results on this benchmark. These figures are "
      "useful for regression and trade-off tracking, not independent validation.\n")

    w("## Event-level results (all seeds combined)\n")
    w("| Configuration | Malicious events caught | Malicious events missed | Benign events falsely flagged | Precision | Recall | False alerts per 1,000 benign events |")
    w("|---|---|---|---|---|---|---|")
    for name, (label, _) in CONFIGS.items():
        c = res[name]["confusion"]
        w(f"| {label} | {c['tp']:,} | {c['fn']:,} | {c['fp']:,} | {pct(ratio(c['tp'], c['tp'] + c['fp']))} | "
          f"{pct(ratio(c['tp'], c['tp'] + c['fn']))} | {1000 * ratio(c['fp'], c['fp'] + c['tn']):.1f} |")
    w("\nEvent recall is deliberately harsh: it counts every event of an attack, including early steps of a slow "
      "attack that are indistinguishable from normal use. The episode view below is the fairer measure of whether an "
      "attack is noticed at all.\n")

    w("## Attack episodes detected (at least one alert)\n")
    w("| Attack | Episodes | " + " | ".join(CONFIGS[n][0] for n in CONFIGS) + " | Median events before first alert (full engine) |")
    w("|---|---|" + "---|" * len(CONFIGS) + "---|")
    for a in ATTACKS:
        cells, total = [], 0
        for name in CONFIGS:
            eps = [e for e in res[name]["episodes"] if e["kind"] == a]
            total = len(eps)
            cells.append(f"{sum(e['detected'] for e in eps)}/{total} ({pct(ratio(sum(e['detected'] for e in eps), total), 0)})")
        firsts = [e["events_before_first_alert"] for e in res["full_default"]["episodes"]
                  if e["kind"] == a and e["events_before_first_alert"] is not None]
        w(f"| `{a}` | {total} | " + " | ".join(cells) + f" | {statistics.median(firsts) if firsts else 'n/a'} |")
    cells = []
    for name in CONFIGS:
        eps = res[name]["episodes"]
        cells.append(f"**{sum(e['detected'] for e in eps)}/{len(eps)} ({pct(ratio(sum(e['detected'] for e in eps), len(eps)), 0)})**")
    w(f"| **All attacks** | {len(res['full_default']['episodes'])} | " + " | ".join(cells) + " | |")
    w("\n\"Median events before first alert\" counts how many attack events happened before the first one was "
      "flagged (0 means the first event was flagged). The system alerts after an access; it does not block it.\n")

    w("## False alerts on benign activity\n")
    w("| Benign activity | Events | " + " | ".join(CONFIGS[n][0] for n in CONFIGS) + " |")
    w("|---|---|" + "---|" * len(CONFIGS))
    for kind in BENIGN_KINDS:
        total = res["full_default"]["benign"][kind][1]
        cells = [f"{res[n]['benign'][kind][0]:,} ({pct(ratio(res[n]['benign'][kind][0], total), 2)})" for n in CONFIGS]
        w(f"| `{kind}` | {total:,} | " + " | ".join(cells) + " |")

    w("\n### Where the false alerts on ordinary activity come from\n")
    w("Ordinary events only, split by the user's normal working size. The fixed Low limit is "
      f"{DEFAULT_SETTINGS['low_max']} rows, so anyone whose normal reads exceed it will trip the volume rule all day.\n")
    w("| User profile | Typical size (median rows) | Ordinary events | " + " | ".join(CONFIGS[n][0] for n in CONFIGS) + " |")
    w("|---|---|---|" + "---|" * len(CONFIGS))
    for profile, (mu, _, _) in PROFILES.items():
        total = res["full_default"]["by_profile"][profile][1]
        cells = [f"{res[n]['by_profile'][profile][0]:,} ({pct(ratio(res[n]['by_profile'][profile][0], total), 1)})" for n in CONFIGS]
        w(f"| `{profile}` | about {2.718281828 ** mu:.0f} | {total:,} | " + " | ".join(cells) + " |")

    w("\n## Variation between organisations (full engine)\n")
    w("Minimum / median / maximum across the seeds:\n")
    w("| Measure | Min / median / max |")
    w("|---|---|")
    ps = res["full_default"]["per_seed"]
    w(f"| Attack episodes detected | {_spread([p['episode_recall'] for p in ps])} |")
    w(f"| False alerts among benign events | {_spread([p['benign_fpr'] for p in ps])} |")
    w(f"| Event precision | {_spread([p['precision'] for p in ps])} |")
    w(f"| Event recall | {_spread([p['event_recall'] for p in ps])} |")

    w("\n## What the numbers show\n")
    full, base, mid = res["full_default"], res["thresholds_only"], res["rules_no_anomaly"]

    def rate(r, kind):
        return ratio(sum(e["detected"] for e in r["episodes"] if e["kind"] == kind),
                     sum(1 for e in r["episodes"] if e["kind"] == kind))

    missed = [(a, rate(full, a)) for a in ATTACKS if rate(full, a) is not None and rate(full, a) < 1]
    for a, r in missed:
        w(f"- **Weakness:** `{a}` attacks were detected in only {pct(r, 0)} of episodes by the full engine "
          f"({ATTACK_NOTES[a]}).")
    if not missed:
        w("- Every attack type was detected in every episode by the full engine on this data.")
    for kind in BENIGN_KINDS:
        f_rate = ratio(full["benign"][kind][0], full["benign"][kind][1])
        if f_rate and f_rate > 0.05:
            w(f"- **False alerts:** {pct(f_rate, 0)} of `{kind}` events were flagged ({BENIGN_NOTES[kind]}). "
              "The rules cannot tell this legitimate activity from an attack.")
    w("- Legitimate exports remain indistinguishable from unauthorized exports because events do not carry trusted "
      "approval or workload context; the evaluation flags all labelled legitimate exports.")
    ana_gain = [(a, rate(mid, a), rate(full, a)) for a in ATTACKS if rate(full, a) != rate(mid, a)]
    for a, before, after in ana_gain:
        w(f"- The per-user anomaly rule changed detection of `{a}` from {pct(before, 0)} to {pct(after, 0)}.")
    if not ana_gain:
        w("- The per-user anomaly rule did not change episode detection for any attack type on this data.")
    fp_mid = ratio(mid["confusion"]["fp"], mid["confusion"]["fp"] + mid["confusion"]["tn"])
    fp_full = ratio(full["confusion"]["fp"], full["confusion"]["fp"] + full["confusion"]["tn"])
    w(f"- Cost of the anomaly rule: false alerts among benign events went from {pct(fp_mid, 2)} to {pct(fp_full, 2)}.")
    by = {p: ratio(full["by_profile"][p][0], full["by_profile"][p][1]) for p in PROFILES}
    worst = max(by, key=lambda p: by[p] or 0)
    w(f"- **Main cause of false alerts:** `{worst}` users had {pct(by[worst], 0)} of their ordinary events flagged. "
      f"Their typical size is about {2.718281828 ** PROFILES[worst][0]:.0f} rows, against a fixed Low limit of "
      f"{DEFAULT_SETTINGS['low_max']}. Fixed global thresholds cannot adapt to users whose normal volume is above them, "
      "and the per-user anomaly rule only adds alerts, it never lowers them.")
    slow = [(a, statistics.median([e["events_before_first_alert"] for e in full["episodes"]
                                   if e["kind"] == a and e["events_before_first_alert"] is not None]))
            for a in ATTACKS if rate(full, a) == 1.0]
    for a, m in slow:
        if m > 0:
            w(f"- `{a}` was always detected, but only after a median of {m:g} attack events had already happened.")
    w(f"- Volume thresholds alone detected {pct(ratio(sum(e['detected'] for e in base['episodes']), len(base['episodes'])), 0)} "
      f"of attack episodes, the full engine {pct(ratio(sum(e['detected'] for e in full['episodes']), len(full['episodes'])), 0)}.")

    w("\n## Limits of this evaluation\n")
    w("- The data, the attacks and the labels were all written by the same person who wrote the detector. Good "
      "results here show the rules do what they were designed to do, not that they would catch real attackers.")
    w("- Attack types reflect assumptions about what insiders do. Real attackers can behave differently, and the "
      "`sub_threshold_drip` and `gradual_ramp` cases show that an attacker who knows the thresholds can avoid them.")
    w("- The headline false alert rate depends on a choice made by the author: a quarter of the users are "
      "\"heavy\" analysts whose normal reads exceed the 20-row Low limit. With fewer such users the rate would be "
      "much lower; with more it would be higher. Read the by-profile table, not just the total.")
    w("- The legitimate-activity cases are few and simple. Real workloads (month-end reports, batch jobs, new "
      "starters with no history) would produce more and different false alerts.")
    c = full["confusion"]
    w(f"- Precision depends on how common attacks are. Here {pct(ratio(c['tp'] + c['fn'], sum(c.values())))} of events "
      "are malicious, far more than in real systems, so real precision would be lower for the same false alert rate.")
    w("- Episodes within one organisation are not independent samples of the real world, so the spread between "
      "seeds shows generator variation, not a confidence interval for real performance.")
    w("- Detection happens after the access. The system raises alerts; it does not block queries.")
    w("- Reproduce with `python -m sentinel.evaluation` (takes a few seconds). Changing the code, the seeds or the "
      "settings changes the numbers.")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the detection engine on labelled synthetic scenarios.")
    parser.add_argument("--seeds", type=int, default=DEFAULT_SEEDS, help="number of synthetic organisations")
    parser.add_argument("--first-seed", type=int, default=FIRST_SEED)
    parser.add_argument("--out", default=str(BASE_DIR / "docs" / "EVALUATION.md"), help="report path")
    parser.add_argument("--print", action="store_true", help="print the report instead of writing a file")
    args = parser.parse_args()
    seeds = list(range(args.first_seed, args.first_seed + args.seeds))
    report = render_report(run_evaluation(seeds))
    if args.print:
        print(report)
        return
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")
    print(f"Evaluated {len(seeds)} synthetic organisations. Report written to {out}")


if __name__ == "__main__":
    main()
