#!/usr/bin/env python3
"""Render demo/transcript.txt as a terminal-typing GIF.

The transcript is generated from real CLI runs (scripts/capture-demo.sh);
this script only renders it, never edits the content.

Frames are written as PNGs to a temp dir and encoded with ffmpeg
(streaming, low memory) instead of holding every frame in RAM: a 151-line
transcript at full canvas size OOMs the PIL-only path.
"""
from PIL import Image, ImageDraw, ImageFont
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FRAMES_DIR = "/tmp/deleguard-gif-frames"

W = 1240
BG = (18, 18, 24)
FG = (220, 220, 220)
DIM = (150, 150, 160)
GREEN = (120, 220, 130)
YELLOW = (235, 200, 100)
RED = (240, 110, 110)
CYAN = (120, 200, 230)

font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 12)
bold = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 12)
LINE_H = 16

lines = open(os.path.join(ROOT, "demo", "transcript.txt")).read().splitlines()
# Fixed-height scrolling terminal viewport: the transcript is 151 lines,
# so a full-height canvas (1240x2474) OOMs the encoder. Show the last
# VIEW_LINES lines like a real terminal scrolling; content is unchanged.
VIEW_LINES = 38
H = 14 + VIEW_LINES * LINE_H + 44

def color_for(line: str):
    if line.startswith("$"):
        return GREEN
    if line.startswith("#"):
        return DIM
    if "VERDICT DENY" in line or "FAIL" in line:
        return RED
    if "VERDICT ALLOW" in line or "verify OK" in line:
        return GREEN
    if "NEEDS-APPROVAL" in line:
        return YELLOW
    if line.startswith("exit: 1"):
        return RED
    if line.startswith("exit: 2"):
        return YELLOW
    if line.startswith("exit: 0"):
        return GREEN
    if "approval" in line.lower():
        return CYAN
    return FG

shutil.rmtree(FRAMES_DIR, ignore_errors=True)
os.makedirs(FRAMES_DIR)

def render(canvas_tmp):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    y = 14
    for text, color in canvas_tmp[-VIEW_LINES:]:
        f = bold if text.startswith("$") else font
        d.text((14, y), text, font=f, fill=color)
        y += LINE_H
        if y > H - 30:
            break
    d.rectangle([14, H - 24, 22, H - 12], fill=GREEN)
    return img

n = 0
def save(img):
    global n
    n += 1
    img.save(os.path.join(FRAMES_DIR, f"frame{n:04d}.png"))

# Title card (2.5s at 20 fps).
title = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(title)
d.text((14, 120), "deleguard - is this exact action authorized?", font=bold, fill=GREEN)
d.text((14, 170), "1. search a flight on united.com: ALLOW, exit 0", font=font, fill=FG)
d.text((14, 200), "2. book a $450 flight: NEEDS-APPROVAL, exit 2", font=font, fill=FG)
d.text((14, 230), "3. approve it (bound to the exact action) -> book: ALLOW", font=font, fill=FG)
d.text((14, 260), "4. $900 over the $500 limit, kayak.com, sub-agent: DENY", font=font, fill=FG)
d.text((14, 290), "5. expired approval: DENY - then audit + verify OK", font=font, fill=FG)
d.text((14, 360), "zero-dep CLI - offline, no API key, no server", font=font, fill=DIM)
d.text((14, 390), "synthetic United travel fixture, real CLI output", font=font, fill=DIM)
for _ in range(50):
    save(title.copy())

canvas: list[tuple[str, tuple]] = []
for line in lines:
    color = color_for(line)
    # Two typing steps per line + one hold: ~3 frames/line keeps the
    # total near 30 s at 20 fps without holding frames in memory.
    half = line[: max(1, len(line) // 2)]
    save(render(canvas + [(half, color)]))
    save(render(canvas + [(line, color)]))
    canvas.append((line, color))
    save(render(canvas))

out = os.path.join(ROOT, "demo", "deleguard-demo.gif")
cmd = [
    "ffmpeg", "-y", "-v", "error",
    "-framerate", "20", "-i", os.path.join(FRAMES_DIR, "frame%04d.png"),
    "-vf", "split[s0][s1];[s0]palettegen=max_colors=256[p];[s1][p]paletteuse",
    out,
]
res = subprocess.run(cmd)
if res.returncode != 0:
    print("ffmpeg failed", file=sys.stderr)
    sys.exit(1)
shutil.rmtree(FRAMES_DIR, ignore_errors=True)
size = os.path.getsize(out)
print(f"GIF written: {out} ({n} frames, {n * 50 / 1000:.1f}s, {size} bytes)")
