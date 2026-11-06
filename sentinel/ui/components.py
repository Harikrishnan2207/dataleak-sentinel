"""Small HTML building blocks (all dynamic text is escaped)."""
from __future__ import annotations

from html import escape

from ..config import RISK_COLORS

LEVEL_ICON = {"Low": "🟢", "Medium": "🟡", "High": "🔴"}


def risk_label(level: str) -> str:
    return f"{LEVEL_ICON.get(level, '⚪')} {level}"


def page_header(title: str, subtitle: str) -> str:
    return (
        f'<div class="page-title">{escape(title)}</div>'
        f'<div class="page-sub">{escape(subtitle)}</div>'
    )


def kpi(label: str, value, sub: str = "", color: str = "#38BDF8") -> str:
    shown = f"{value:,}" if isinstance(value, (int, float)) else escape(str(value))
    return (
        f'<div class="kpi" style="--c:{color}">'
        f'<div class="kpi-label">{escape(label)}</div>'
        f'<div class="kpi-value">{shown}</div>'
        f'<div class="kpi-sub">{escape(sub)}</div></div>'
    )


def chip(level: str) -> str:
    return f'<span class="chip chip-{escape(level.lower())}">{escape(level)}</span>'


def alert_card(row) -> str:
    color = RISK_COLORS.get(row.risk_level, "#F87171")
    return (
        f'<div class="alert-card" style="--c:{color}"><div class="alert-top">'
        f'{chip(row.risk_level)}'
        f'<span class="alert-user">{escape(str(row.username))}</span>'
        f'<span class="alert-meta">{row.timestamp:%Y-%m-%d %H:%M:%S}</span>'
        f'<span class="alert-meta">{int(row.records_accessed):,} records</span>'
        f'<span class="alert-meta">risk score {int(row.risk_score)}</span></div>'
        f'<div class="alert-reason">{escape(str(row.reason))}</div></div>'
    )
