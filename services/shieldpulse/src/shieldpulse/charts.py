"""Server-rendered SVG charts. Colors come from CSS classes, so charts follow the active theme."""

from __future__ import annotations

from datetime import date
from html import escape
from typing import Any

WIDTH, HEIGHT = 720, 300
PAD_L, PAD_R, PAD_T, PAD_B = 52, 16, 16, 28
TICKS = 4
# Axis steps people read at a glance: 1m, 2m, 5m, 10m, 15m, 30m, 1h, 2h, 4h, 8h, 12h, 1d.
NICE_STEPS = (60, 120, 300, 600, 900, 1800, 3600, 7200, 14400, 28800, 43200, 86400)


def nice_top(peak: float) -> int:
    """Smallest round axis maximum (TICKS x a nice step) with headroom above `peak`."""
    for step in NICE_STEPS:
        if step * TICKS >= peak * 1.1:
            return step * TICKS
    return NICE_STEPS[-1] * TICKS


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    seconds = int(round(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s" if secs else f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"


def mttr_line_chart(points: list[dict[str, Any]], target_sec: int) -> str:
    """Daily MTTR line with an SLA target line. Days without incidents leave a gap."""
    values = [p["mttr_seconds"] for p in points if p["mttr_seconds"] is not None]
    top = nice_top(max(values + [target_sec]))
    n = max(len(points) - 1, 1)
    plot_w, plot_h = WIDTH - PAD_L - PAD_R, HEIGHT - PAD_T - PAD_B

    def x(i: int) -> float:
        return PAD_L + plot_w * i / n

    def y(v: float) -> float:
        return PAD_T + plot_h * (1 - v / top)

    parts = [
        f'<svg class="chart" viewBox="0 0 {WIDTH} {HEIGHT}" role="img" '
        f'aria-label="Daily mean time to remediate over the last {len(points)} days, target {escape(format_duration(target_sec))}">'
    ]
    for k in range(1, TICKS + 1):
        frac = k / TICKS
        gy = PAD_T + plot_h * (1 - frac)
        parts.append(f'<line class="chart-grid" x1="{PAD_L}" x2="{WIDTH - PAD_R}" y1="{gy:.1f}" y2="{gy:.1f}"/>')
        parts.append(f'<text class="chart-axis" x="{PAD_L - 8}" y="{gy + 4:.1f}" text-anchor="end">'
                     f'{escape(format_duration(top * frac))}</text>')

    ty = y(target_sec)
    parts.append(f'<line class="chart-target" x1="{PAD_L}" x2="{WIDTH - PAD_R}" y1="{ty:.1f}" y2="{ty:.1f}"/>')
    parts.append(f'<text class="chart-target-label" x="{WIDTH - PAD_R}" y="{ty - 6:.1f}" text-anchor="end">'
                 f'SLA target {escape(format_duration(target_sec))}</text>')

    # Contiguous runs of days with data become separate segments (gaps on empty days).
    segment: list[tuple[float, float]] = []
    segments: list[list[tuple[float, float]]] = []
    for i, p in enumerate(points):
        if p["mttr_seconds"] is None:
            if segment:
                segments.append(segment)
            segment = []
        else:
            segment.append((x(i), y(p["mttr_seconds"])))
    if segment:
        segments.append(segment)
    for seg in segments:
        coords = " ".join(f"{px:.1f},{py:.1f}" for px, py in seg)
        if len(seg) > 1:
            base = PAD_T + plot_h
            parts.append(f'<polygon class="chart-area" points="{seg[0][0]:.1f},{base} {coords} {seg[-1][0]:.1f},{base}"/>')
            parts.append(f'<polyline class="chart-line" points="{coords}"/>')

    for i, p in enumerate(points):
        if p["mttr_seconds"] is None:
            continue
        over = " is-over" if p["mttr_seconds"] > target_sec else ""
        day: date = p["day"]
        label = f"{day:%b} {day.day}: {format_duration(p['mttr_seconds'])} across {p['incidents']} incident(s)"
        parts.append(f'<circle class="chart-dot{over}" cx="{x(i):.1f}" cy="{y(p["mttr_seconds"]):.1f}" r="4">'
                     f'<title>{escape(label)}</title></circle>')

    for i in sorted({0, len(points) // 2, len(points) - 1}):
        if 0 <= i < len(points):
            day = points[i]["day"]
            anchor = "start" if i == 0 else "end" if i == len(points) - 1 else "middle"
            parts.append(f'<text class="chart-axis" x="{x(i):.1f}" y="{HEIGHT - 8}" text-anchor="{anchor}">'
                         f'{day:%b} {day.day}</text>')
    if not values:
        parts.append(f'<text class="chart-empty" x="{WIDTH / 2}" y="{HEIGHT / 2}" text-anchor="middle">'
                     "No resolved P1/P2 incidents in this period</text>")
    parts.append("</svg>")
    return "".join(parts)
