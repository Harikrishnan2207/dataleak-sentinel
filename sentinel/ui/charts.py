"""Plotly figures, styled for the dark navy theme."""
from __future__ import annotations

import pandas as pd
import plotly.express as px

from ..config import RISK_COLORS, RISK_LEVELS

TEXT = "#C5D3E5"
GRID = "#1E3652"
BUCKETS = {"15 minutes": "15min", "1 hour": "1h", "6 hours": "6h"}


def _style(fig, height: int = 340):
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=height,
        margin=dict(l=10, r=10, t=48, b=10),
        font=dict(color=TEXT),
        title=dict(font=dict(size=15), x=0),
        legend=dict(orientation="h", y=-0.18, x=0, title_text=""),
    )
    fig.update_xaxes(gridcolor=GRID, zerolinecolor=GRID, title_text="")
    fig.update_yaxes(gridcolor=GRID, zerolinecolor=GRID)
    return fig


def activity_trend(df: pd.DataFrame, bucket: str):
    grouped = (
        df.groupby([pd.Grouper(key="timestamp", freq=bucket), "risk_level"])
        .size().reset_index(name="events")
    )
    fig = px.bar(
        grouped, x="timestamp", y="events", color="risk_level",
        color_discrete_map=RISK_COLORS, category_orders={"risk_level": RISK_LEVELS},
        title="Access activity over time",
    )
    fig.update_yaxes(title_text="Access events")
    return _style(fig)


def records_vs_thresholds(df: pd.DataFrame, cfg: dict[str, int]):
    fig = px.scatter(
        df, x="timestamp", y="records_accessed", color="risk_level",
        color_discrete_map=RISK_COLORS, category_orders={"risk_level": RISK_LEVELS},
        hover_data={"username": True, "access_type": True, "risk_score": True, "timestamp": "|%Y-%m-%d %H:%M"},
        log_y=True, title="Records per access vs. thresholds",
    )
    fig.update_traces(marker=dict(size=8, opacity=0.85))
    fig.add_hline(y=cfg["low_max"], line_dash="dot", line_color=RISK_COLORS["Low"],
                  annotation_text=f"low limit ({cfg['low_max']})", annotation_position="top left")
    fig.add_hline(y=cfg["medium_max"], line_dash="dot", line_color=RISK_COLORS["High"],
                  annotation_text=f"high threshold ({cfg['medium_max']})", annotation_position="top left")
    fig.update_yaxes(title_text="Records accessed (log scale)")
    return _style(fig)


def risk_distribution(df: pd.DataFrame):
    counts = df["risk_level"].value_counts().reindex(RISK_LEVELS).fillna(0).reset_index()
    counts.columns = ["risk_level", "events"]
    fig = px.pie(
        counts, names="risk_level", values="events", hole=0.6,
        color="risk_level", color_discrete_map=RISK_COLORS,
        category_orders={"risk_level": RISK_LEVELS}, title="Risk level distribution",
    )
    fig.update_traces(sort=False, textinfo="value+percent", marker=dict(line=dict(color="#07111F", width=2)))
    return _style(fig)


def top_users(df: pd.DataFrame, limit: int = 8):
    agg = (
        df.groupby("username")
        .agg(records=("records_accessed", "sum"), top_score=("risk_score", "max"))
        .reset_index()
    )
    agg["Highest risk"] = pd.cut(
        agg["top_score"], bins=[-1, 25, 60, 101], labels=RISK_LEVELS
    ).astype(str)
    agg = agg.sort_values("records", ascending=False).head(limit).sort_values("records")
    fig = px.bar(
        agg, x="records", y="username", orientation="h", color="Highest risk",
        color_discrete_map=RISK_COLORS, category_orders={"Highest risk": RISK_LEVELS},
        title="Top users by total records accessed",
    )
    fig.update_xaxes(title_text="Total records accessed")
    fig.update_yaxes(title_text="")
    return _style(fig)
