"""Streamlit pages. Each function renders one sidebar destination."""
from __future__ import annotations

import time
from html import escape

import pandas as pd
import streamlit as st

from ..config import DEFAULT_SETTINGS, RISK_COLORS, RISK_LEVELS
from ..scenario import run_guided_scenario
from ..simulator import ACCESS_TYPES, EMPLOYEES, generate_demo_events
from . import charts
from . import components as ui

# ------------------------------------------------------------------ helpers


def flash(message: str, kind: str = "success") -> None:
    st.session_state["_flash"] = (kind, message)


def show_flash() -> None:
    item = st.session_state.pop("_flash", None)
    if item:
        getattr(st, item[0])(item[1])


def header(title: str, subtitle: str) -> None:
    st.markdown(ui.page_header(title, subtitle), unsafe_allow_html=True)
    show_flash()


def generate_demo(db, seed: int) -> dict:
    db.add_events(generate_demo_events(seed=int(seed)))
    return db.rescan()


def empty_state(db, key: str) -> None:
    st.markdown(
        '<div class="empty-box">No access activity stored yet. Generate a batch of synthetic '
        "activity to see the detection engine work.</div>",
        unsafe_allow_html=True,
    )
    if st.button("Generate demo data", type="primary", key=f"gen_{key}"):
        summary = generate_demo(db, 42)
        flash(f"Generated {summary['events']} access events and {summary['alerts']} alerts.")
        st.rerun()


def activity_table(df: pd.DataFrame) -> pd.DataFrame:
    out = pd.DataFrame({
        "Log ID": df["log_id"],
        "User ID": df["user_id"],
        "Username": df["username"],
        "Department": df["department"],
        "Timestamp": df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S"),
        "Access Type": df["access_type"],
        "Records Accessed": df["records_accessed"],
        "Risk Score": df["risk_score"],
        "Risk Level": df["risk_level"].map(ui.risk_label),
        "Detection Reason": df["reason"],
    })
    return out


TABLE_CONFIG = {
    "Risk Score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%d"),
    "Records Accessed": st.column_config.NumberColumn("Records Accessed", format="%d"),
    "Detection Reason": st.column_config.TextColumn("Detection Reason", width="large"),
}

# ---------------------------------------------------------------- dashboard


def dashboard(db) -> None:
    header("Dashboard", "Bulk data extraction monitoring across simulated database access logs")
    activity, alerts, cfg = db.activity_df(), db.alerts_df(), db.get_settings()
    if activity.empty:
        empty_state(db, "dashboard")
        return

    total = len(activity)
    levels = activity["risk_level"]
    normal = int((levels == "Low").sum())
    medium = int((levels == "Medium").sum())
    high = int((levels == "High").sum())
    suspicious = medium + high
    flagged = int(alerts["user_id"].nunique())

    cols = st.columns(6)
    cards = [
        ("Total access attempts", total, f"{activity['user_id'].nunique()} users monitored", "#38BDF8"),
        ("Normal activities", normal, f"{normal / total:.0%} of attempts", RISK_COLORS["Low"]),
        ("Suspicious activities", suspicious, f"{medium} medium, {high} high", RISK_COLORS["Medium"]),
        ("Flagged users", flagged, "users with at least one alert", RISK_COLORS["High"]),
        ("High-risk events", high, f"peak risk score {int(activity['risk_score'].max())}", RISK_COLORS["High"]),
        ("Unreviewed alerts", int((alerts["status"] == "New").sum()), "require attention", RISK_COLORS["High"]),
    ]
    for col, (label, value, sub, color) in zip(cols, cards):
        col.markdown(ui.kpi(label, value, sub, color), unsafe_allow_html=True)

    st.markdown('<div class="section-title">Activity trends</div>', unsafe_allow_html=True)
    left, right = st.columns([3, 2])
    with left:
        bucket_label = st.selectbox("Time interval", list(charts.BUCKETS), index=1, key="trend_bucket")
        st.plotly_chart(charts.activity_trend(activity, charts.BUCKETS[bucket_label]), width="stretch")
    with right:
        st.write("")
        st.write("")
        st.write("")
        st.plotly_chart(charts.risk_distribution(activity), width="stretch")

    left, right = st.columns([3, 2])
    with left:
        st.plotly_chart(charts.records_vs_thresholds(activity, cfg), width="stretch")
    with right:
        st.plotly_chart(charts.top_users(activity), width="stretch")

    st.markdown('<div class="section-title">Recent security alerts</div>', unsafe_allow_html=True)
    if alerts.empty:
        st.info("No alerts raised. All stored activity is within the configured thresholds.")
    else:
        recent = alerts.head(6)
        st.markdown("".join(ui.alert_card(r) for r in recent.itertuples()), unsafe_allow_html=True)
        st.caption(f"Showing the latest {len(recent)} of {len(alerts)} alerts. Open Security Alerts for the full list.")


# ------------------------------------------------------------ user activity


def user_activity(db) -> None:
    header("User Activity", "Every monitored access with its risk score and level")
    df = db.activity_df()
    if df.empty:
        empty_state(db, "activity")
        return

    c1, c2, c3, c4 = st.columns([2, 1.3, 1.3, 1.3])
    query = c1.text_input("Search", placeholder="Username, user ID, department or reason")
    levels = c2.multiselect("Risk level", RISK_LEVELS, default=RISK_LEVELS)
    depts = c3.multiselect("Department", sorted(df["department"].unique()))
    types = c4.multiselect("Access type", sorted(df["access_type"].unique()))

    view = df[df["risk_level"].isin(levels)]
    if depts:
        view = view[view["department"].isin(depts)]
    if types:
        view = view[view["access_type"].isin(types)]
    if query.strip():
        q = query.strip().lower()
        haystack = (
            view["username"] + " " + view["user_id"] + " " + view["department"] + " " + view["reason"]
        ).str.lower()
        view = view[haystack.str.contains(q, regex=False)]

    st.caption(f"Showing {len(view):,} of {len(df):,} access events. Click a column header to sort.")
    st.dataframe(activity_table(view), hide_index=True, width="stretch", height=560, column_config=TABLE_CONFIG)


# ---------------------------------------------------------- security alerts


def security_alerts(db) -> None:
    header("Security Alerts", "Raised whenever an access is scored Medium or High")
    alerts = db.alerts_df()
    if alerts.empty:
        st.info("No alerts yet. Alerts appear when an access exceeds the configured thresholds or triggers a behaviour rule.")
        if db.table_counts()["access_logs"] == 0:
            empty_state(db, "alerts")
        return

    n_high = int((alerts["risk_level"] == "High").sum())
    n_med = int((alerts["risk_level"] == "Medium").sum())
    cols = st.columns(4)
    for col, (label, value, sub, color) in zip(cols, [
        ("Total alerts", len(alerts), "all severities", "#38BDF8"),
        ("High severity", n_high, "bulk or repeated extraction", RISK_COLORS["High"]),
        ("Medium severity", n_med, "elevated volume", RISK_COLORS["Medium"]),
        ("Flagged users", int(alerts["user_id"].nunique()), "distinct users", RISK_COLORS["High"]),
    ]):
        col.markdown(ui.kpi(label, value, sub, color), unsafe_allow_html=True)

    st.write("")
    c1, c2, c3 = st.columns([2, 1.3, 1.3])
    query = c1.text_input("Search alerts", placeholder="Username or reason", key="alert_search")
    sev = c2.multiselect("Severity", ["High", "Medium"], default=["High", "Medium"], key="alert_sev")
    statuses = c3.multiselect("Status", ["New", "Reviewed"], default=["New", "Reviewed"], key="alert_status")
    view = alerts[alerts["risk_level"].isin(sev) & alerts["status"].isin(statuses)]
    if query.strip():
        q = query.strip().lower()
        hay = (view["username"] + " " + view["reason"]).str.lower()
        view = view[hay.str.contains(q, regex=False)]

    table = pd.DataFrame({
        "Alert ID": view["alert_id"],
        "Username": view["username"],
        "Timestamp": view["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S"),
        "Records Accessed": view["records_accessed"],
        "Risk Score": view["risk_score"],
        "Severity": view["risk_level"].map(ui.risk_label),
        "Status": view["status"].map({"New": "🔵 New", "Reviewed": "✅ Reviewed"}),
        "Reason": view["reason"],
    })
    st.caption(f"Showing {len(view):,} of {len(alerts):,} alerts, newest first.")
    st.dataframe(table, hide_index=True, width="stretch", height=420, column_config={
        "Risk Score": TABLE_CONFIG["Risk Score"],
        "Records Accessed": TABLE_CONFIG["Records Accessed"],
        "Reason": st.column_config.TextColumn("Reason", width="large"),
    })

    st.markdown('<div class="section-title">Mark reviewed</div>', unsafe_allow_html=True)
    alert_id = st.number_input("Alert ID to mark reviewed", min_value=1, step=1, value=1, key="review_alert_id")
    if st.button("Mark reviewed", key="mark_alert_reviewed"):
        if int(alert_id) not in set(alerts["alert_id"].astype(int)):
            st.error("Alert ID not found in the current alert list.")
        else:
            db.mark_reviewed(int(alert_id))
            flash(f"Alert {int(alert_id)} marked as reviewed.")
            st.rerun()

    st.download_button("Download alerts as CSV", table.to_csv(index=False).encode("utf-8"),
                       "dataleak_alerts.csv", "text/csv")

    st.markdown('<div class="section-title">Flagged users</div>', unsafe_allow_html=True)
    users = (
        alerts.groupby(["user_id", "username"])
        .agg(Alerts=("alert_id", "count"), HighestScore=("risk_score", "max"),
             RecordsInAlerts=("records_accessed", "sum"), LastAlert=("timestamp", "max"))
        .reset_index().sort_values(["HighestScore", "Alerts"], ascending=False)
    )
    users_table = pd.DataFrame({
        "User ID": users["user_id"], "Username": users["username"], "Alerts": users["Alerts"],
        "Highest Risk Score": users["HighestScore"], "Records in Alerts": users["RecordsInAlerts"],
        "Last Alert": users["LastAlert"].dt.strftime("%Y-%m-%d %H:%M:%S"),
    })
    st.dataframe(users_table, hide_index=True, width="stretch", column_config={
        "Highest Risk Score": TABLE_CONFIG["Risk Score"],
        "Records in Alerts": TABLE_CONFIG["Records Accessed"],
    })


# --------------------------------------------------------------- audit logs


def audit_logs(db) -> None:
    header("Audit Logs", "Every access and detection result stored in SQLite, kept across restarts")
    counts = db.table_counts()
    size_kb = db.path.stat().st_size / 1024 if db.path.exists() else 0
    cols = st.columns(4)
    for col, (label, value, sub) in zip(cols, [
        ("Access logs stored", counts["access_logs"], "table access_logs"),
        ("Detection results", counts["detections"], "table detections"),
        ("Alerts stored", counts["alerts"], "table alerts"),
        ("Database size", f"{size_kb:,.0f} KB", db.path.name),
    ]):
        col.markdown(ui.kpi(label, value, sub), unsafe_allow_html=True)
    st.caption(f"Database file: {db.path}")

    df = db.activity_df()
    if df.empty:
        empty_state(db, "audit")
        return
    table = activity_table(df)
    st.dataframe(table, hide_index=True, width="stretch", height=520, column_config=TABLE_CONFIG)
    st.download_button("Download audit log as CSV", df.assign(
        timestamp=df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")).to_csv(index=False).encode("utf-8"),
        "dataleak_audit_log.csv", "text/csv")


# ----------------------------------------------------------- detection rules


def detection_rules(db) -> None:
    header("Detection Rules", "Thresholds and behaviour rules used to score every access")
    cfg = db.get_settings()

    st.markdown(
        f"""
| Volume per access | Base risk |
|---|---|
| 1 to {cfg['low_max']:,} records | 🟢 Low |
| {cfg['low_max'] + 1:,} to {cfg['medium_max']:,} records | 🟡 Medium |
| More than {cfg['medium_max']:,} records | 🔴 High |
"""
    )

    with st.form("rules_form"):
        st.markdown("**Volume thresholds**")
        a, b = st.columns(2)
        low_max = a.number_input("Low-risk limit (max records)", 1, 1_000_000, cfg["low_max"])
        medium_max = b.number_input("Medium-risk limit (max records)", 2, 1_000_000, cfg["medium_max"])

        st.markdown("**Repeated high-volume access**")
        a, b, c = st.columns(3)
        repeat_min = a.number_input("High-volume starts at (records)", 1, 1_000_000, cfg["repeat_min_records"])
        repeat_count = b.number_input("Number of accesses", 2, 1000, cfg["repeat_count"])
        repeat_window = c.number_input("Window (minutes)", 1, 1440, cfg["repeat_window_min"])

        st.markdown("**Unusual access frequency**")
        a, b = st.columns(2)
        freq_count = a.number_input("Number of accesses", 2, 1000, cfg["freq_count"], key="fc")
        freq_window = b.number_input("Window (minutes)", 1, 1440, cfg["freq_window_min"], key="fw")

        st.markdown("**Cumulative volume**")
        cumulative = st.number_input("Total records in the repeated-access window", 1, 10_000_000,
                                     cfg["cumulative_limit"])
        submitted = st.form_submit_button("Save and re-scan all logs", type="primary")

    if submitted:
        new_cfg = {
            "low_max": low_max, "medium_max": medium_max, "repeat_min_records": repeat_min,
            "repeat_count": repeat_count, "repeat_window_min": repeat_window,
            "freq_count": freq_count, "freq_window_min": freq_window, "cumulative_limit": cumulative,
        }
        errors = db.save_settings(new_cfg)
        if errors:
            for err in errors:
                st.error(err)
        else:
            summary = db.rescan()
            flash(f"Rules saved. Re-scanned {summary['events']} events and rebuilt {summary['alerts']} alerts.")
            st.rerun()

    if st.button("Reset to default rules"):
        db.reset_settings()
        summary = db.rescan()
        flash(f"Default rules restored. Re-scanned {summary['events']} events.")
        st.rerun()

    with st.expander("How the risk score works"):
        st.markdown(
            """
- **Volume** sets a base score: Low is 1 to 25, Medium is 26 to 60, High is 61 to 85 (rising with volume).
- **Repeated high-volume access** adds 15 points when a user makes the configured number of high-volume accesses inside the window.
- **Unusual frequency** adds 10 points when a user makes too many accesses inside a short window, even if each one is small.
- **Cumulative volume** adds 10 points when a user's total records inside the window pass the limit.
- The final score is capped at 100. Scores of 26 to 60 are **Medium** and 61 or more are **High**, and any triggered behaviour rule guarantees at least Medium, so an access that looks harmless on its own can still raise an alert.
- Medium and High accesses raise an alert. These are simple, transparent heuristics, not a trained model.
"""
        )


# -------------------------------------------------------------- demo control


def _render_scenario(result: dict, animate: bool) -> None:
    """Narrate the guided scenario. Every number shown comes from the real result."""
    def pause() -> None:
        if animate:
            time.sleep(0.7)

    n, b = result["normal"], result["bulk"]
    cfg = result["thresholds"]
    nu, bu = n["user"][1], b["user"][1]

    with st.container(border=True):
        st.markdown("**Step 1: A normal user reads a small number of records**")
        st.markdown(f"{nu} ({n['user'][2]}) ran **{n['access_type']}** and read **{n['records']:,} records**.")
    pause()
    with st.container(border=True):
        st.markdown("**Step 2: Another user reads an unusually large number of records**")
        st.markdown(f"{bu} ({b['user'][2]}) ran **{b['access_type']}** and read **{b['records']:,} records**.")
    pause()
    with st.container(border=True):
        st.markdown("**Step 3: The system calculates a risk score**")
        st.markdown(f"{nu}: score **{n['risk_score']}**. {bu}: score **{b['risk_score']}**. "
                    f"Thresholds in use: Low up to {cfg['low_max']:,} records, High above {cfg['medium_max']:,}.")
    pause()
    with st.container(border=True):
        st.markdown("**Step 4: The system identifies suspicious activity**")
        for name, res in ((nu, n), (bu, b)):
            st.markdown(f"{ui.chip(res['risk_level'])} **{escape(name)}**: {escape(res['reason'])}",
                        unsafe_allow_html=True)
    pause()
    with st.container(border=True):
        st.markdown("**Step 5: A security alert is generated**")
        alert = result["bulk_alert"]
        if alert is None:
            st.info(f"No alert was raised for {bu} under the current rules.")
        else:
            st.markdown(f"Alert **#{int(alert['alert_id'])}** created for {bu}, status **{alert['status']}**.")
        if result["normal_alert"] is not None:
            st.markdown(f"{nu} was also flagged (alert #{int(result['normal_alert']['alert_id'])}).")
    pause()
    with st.container(border=True):
        st.markdown("**Step 6: The administrator sees the alert**")
        if alert is not None:
            card = alert.to_frame().T.itertuples()
            st.markdown("".join(ui.alert_card(r) for r in card), unsafe_allow_html=True)
        st.caption(f"Unreviewed alerts is now {result['unreviewed']}. Open Dashboard or Security Alerts to see it there.")
    pause()
    with st.container(border=True):
        st.markdown("**Step 7: The activity is stored in the SQLite audit log**")
        st.dataframe(activity_table(result["audit_rows"]), hide_index=True, width="stretch",
                     column_config=TABLE_CONFIG)
        st.caption(f"Stored in {result['db_name']}. Access logs: {result['counts_before']['access_logs']:,} "
                   f"to {result['counts_after']['access_logs']:,}. Open Audit Logs to see the same rows.")


def demo_control(db) -> None:
    header("Demo Simulation", "Generate synthetic activity to exercise the detection engine")
    st.info("All users and events here are synthetic. Nothing is read from a real database.")

    st.markdown('<div class="section-title">Generate sample activity</div>', unsafe_allow_html=True)
    st.markdown(
        "Each batch contains normal employee activity, medium-risk queries, a high-risk bulk "
        "extraction, a repeated suspicious access pattern and a burst of rapid small queries."
    )
    seed = st.number_input("Random seed (same seed gives the same batch)", 0, 999_999, 42)
    confirm = st.checkbox("I understand clearing deletes all stored logs, detections and alerts")

    b1, b2, b3 = st.columns(3)
    if b1.button("Generate demo data", type="primary", width="stretch"):
        summary = generate_demo(db, seed)
        flash(f"Added {summary['events']} access events in total, {summary['alerts']} alerts raised.")
        st.rerun()
    if b2.button("Clear and regenerate", width="stretch", disabled=not confirm):
        db.clear_data()
        st.session_state.pop("scenario", None)
        summary = generate_demo(db, seed)
        flash(f"Cleared old data and generated {summary['events']} fresh events with {summary['alerts']} alerts.")
        st.rerun()
    if b3.button("Clear all data", width="stretch", disabled=not confirm):
        db.clear_data()
        st.session_state.pop("scenario", None)
        flash("All logs, detections and alerts were deleted. Detection rules were kept.", "info")
        st.rerun()

    st.markdown('<div class="section-title">Guided live scenario</div>', unsafe_allow_html=True)
    st.caption("Plays the full story: a normal access, a bulk extraction, scoring, an alert and the audit record. "
               "The record counts are entered here, not measured from a real query. Scoring, alerts and "
               "SQLite storage are real, and the pauses between steps are only for readability.")
    ca, cb = st.columns(2)
    normal_n = ca.number_input("Normal user records", 1, 100_000, 8, key="sc_normal")
    bulk_n = cb.number_input("Bulk user records", 1, 10_000_000, 3200, key="sc_bulk")
    if st.button("Run guided scenario", type="primary", key="run_scenario"):
        st.session_state["scenario"] = run_guided_scenario(db, int(normal_n), int(bulk_n))
        st.session_state["scenario_animate"] = True
        st.rerun()
    if st.session_state.get("scenario"):
        _render_scenario(st.session_state["scenario"], st.session_state.pop("scenario_animate", False))

    st.markdown('<div class="section-title">Log a single access</div>', unsafe_allow_html=True)
    st.caption("Try your own numbers. The event is stamped with the current time and scored immediately. "
               "Submit several quickly for the same user to trigger the frequency and repeated-access rules.")
    with st.form("manual_event"):
        a, b, c = st.columns([2, 1.5, 1])
        user = a.selectbox("User", EMPLOYEES, format_func=lambda e: f"{e[0]}  {e[1]} ({e[2]})")
        access_type = b.selectbox("Access type", ACCESS_TYPES)
        records = c.number_input("Records accessed", 1, 1_000_000, 15)
        go = st.form_submit_button("Log access event")
    if go:
        res = db.log_event(user[0], user[1], user[2], access_type, int(records))
        kind = {"Low": "success", "Medium": "warning", "High": "error"}[res["risk_level"]]
        flash(f"{user[1]}: {int(records):,} records scored {res['risk_score']} ({res['risk_level']}). {res['reason']}", kind)
        st.rerun()
