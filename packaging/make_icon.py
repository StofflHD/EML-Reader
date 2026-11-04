#!/usr/bin/env python3
"""Draws the EML Reader icon (PNG + SVG) with pycairo, in the style of the notepad-rs icon:
a squircle with the rust gradient (accent colour of the UI theme), an envelope and a header card.

Usage: python3 packaging/make_icon.py   (writes packaging/eml-reader.png/.svg)
"""
import math
import os
import sys

import cairo

HERE = os.path.dirname(os.path.abspath(__file__))

CREAM = "#fbf9f6"
DARK = "#2c2825"
DARKER = "#1b1917"
ACCENT = "#b8411b"


def hexc(h, a=1.0):
    h = h.lstrip("#")
    return (int(h[0:2], 16) / 255, int(h[2:4], 16) / 255, int(h[4:6], 16) / 255, a)


def rounded_rect(cr, x, y, w, h, r):
    cr.new_sub_path()
    cr.arc(x + w - r, y + r, r, -math.pi / 2, 0)
    cr.arc(x + w - r, y + h - r, r, 0, math.pi / 2)
    cr.arc(x + r, y + h - r, r, math.pi / 2, math.pi)
    cr.arc(x + r, y + r, r, math.pi, 3 * math.pi / 2)
    cr.close_path()


def squircle(cr, x, y, s, n=5.0, steps=200):
    """Superellipse like modern app icons."""
    cx, cy, a = x + s / 2, y + s / 2, s / 2
    for i in range(steps + 1):
        t = 2 * math.pi * i / steps
        ct, st = math.cos(t), math.sin(t)
        px = cx + a * math.copysign(abs(ct) ** (2 / n), ct)
        py = cy + a * math.copysign(abs(st) ** (2 / n), st)
        if i == 0:
            cr.move_to(px, py)
        else:
            cr.line_to(px, py)
    cr.close_path()


def envelope(cr, dx, dy, shadow):
    """Envelope with an open flap and a dark header card with accent lines; `shadow` draws
    everything flat in black."""
    def fill(colour, a=1.0):
        cr.set_source_rgba(*(0, 0, 0, 0.28) if shadow else hexc(colour, a))

    # envelope body
    rounded_rect(cr, 40 + dx, 72 + dy, 176, 124, 16)
    fill(CREAM)
    cr.fill()
    if not shadow:
        # flap and side folds
        cr.set_line_width(9)
        cr.set_line_cap(cairo.LINE_CAP_ROUND)
        cr.set_line_join(cairo.LINE_JOIN_ROUND)
        fill("#c9bfb4")
        cr.move_to(54, 88)
        cr.line_to(128, 146)
        cr.line_to(202, 88)
        cr.stroke()
        cr.set_line_width(6)
        cr.move_to(54, 182)
        cr.line_to(104, 140)
        cr.move_to(202, 182)
        cr.line_to(152, 140)
        cr.stroke()
    # header card (bottom right), like a selected row with the accent bar
    rounded_rect(cr, 138 + dx, 150 + dy, 90, 74, 12)
    fill(DARK)
    cr.fill()
    if not shadow:
        cr.save()
        rounded_rect(cr, 138, 150, 90, 74, 12)
        cr.clip()
        cr.rectangle(138, 150, 90, 13)
        fill(ACCENT)
        cr.fill()
        cr.restore()
        cr.set_line_width(7)
        cr.set_line_cap(cairo.LINE_CAP_ROUND)
        for j, (w, c) in enumerate(((22, "#f0773a"), (22, "#f0773a"), (22, "#f0773a"))):
            y = 179 + j * 14
            fill(c)
            cr.move_to(151, y)
            cr.line_to(151 + w, y)
            cr.stroke()
            fill(CREAM)
            cr.move_to(183, y)
            cr.line_to(183 + (30 if j != 1 else 20), y)
            cr.stroke()


def draw(cr, S):
    k = S / 256.0
    cr.scale(k, k)

    # Background: squircle with a rust gradient (accent colour of the UI theme)
    squircle(cr, 8, 8, 240)
    g = cairo.LinearGradient(0, 8, 0, 248)
    g.add_color_stop_rgba(0, *hexc("#f0773a"))
    g.add_color_stop_rgba(1, *hexc("#a8380f"))
    cr.set_source(g)
    cr.fill_preserve()
    cr.set_source_rgba(*hexc("#6b240a", 0.8))
    cr.set_line_width(2)
    cr.stroke()

    # Subtle highlight in the upper half
    cr.save()
    squircle(cr, 8, 8, 240)
    cr.clip()
    hl = cairo.LinearGradient(0, 8, 0, 130)
    hl.add_color_stop_rgba(0, 1, 1, 1, 0.18)
    hl.add_color_stop_rgba(1, 1, 1, 1, 0.0)
    cr.set_source(hl)
    cr.rectangle(0, 0, 256, 130)
    cr.fill()
    cr.restore()

    envelope(cr, 5, 8, True)
    envelope(cr, 0, 0, False)


def main():
    png = os.path.join(HERE, "eml-reader.png")
    svg = os.path.join(HERE, "eml-reader.svg")
    out = sys.argv[1] if len(sys.argv) > 1 else None
    surf = cairo.ImageSurface(cairo.FORMAT_ARGB32, 256, 256)
    draw(cairo.Context(surf), 256)
    surf.write_to_png(out or png)
    if not out:
        s = cairo.SVGSurface(svg, 256, 256)
        draw(cairo.Context(s), 256)
        s.finish()


if __name__ == "__main__":
    main()
