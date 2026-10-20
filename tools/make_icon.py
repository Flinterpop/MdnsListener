"""Generates src/gui/MdnsListener.ico: a teal tile, a dot, and the arcs of
something being heard on the air either side of it. Regenerate rather than hand-edit:

    C:\\Python314\\python.exe tools\\make_icon.py

Needs Pillow. Each size is drawn on its own at 8x and scaled down, so the
small sizes can drop detail instead of blurring it.
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

SIZES: tuple[int, ...] = (16, 20, 24, 32, 40, 48, 64, 128, 256)
OVERSAMPLE = 8
TOP = (22, 150, 160)
BOTTOM = (10, 90, 110)
WHITE = (255, 255, 255, 255)


def tile(size: int) -> Image.Image:
    """The rounded square, shaded top to bottom."""
    assert size > 0
    grad = Image.new("RGBA", (size, size))
    px = grad.load()
    assert px is not None
    for y in range(size):
        t = y / max(size - 1, 1)
        c = tuple(round(a + (b - a) * t) for a, b in zip(TOP, BOTTOM))
        for x in range(size):
            px[x, y] = (c[0], c[1], c[2], 255)
    mask = Image.new("L", (size, size), 0)
    inset = size * 0.04
    ImageDraw.Draw(mask).rounded_rectangle(
        (inset, inset, size - inset, size - inset), radius=size * 0.2, fill=255
    )
    out = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    out.paste(grad, (0, 0), mask)
    return out


def render(px: int) -> Image.Image:
    """One icon size, drawn at OVERSAMPLE times and reduced."""
    assert px in SIZES
    size = px * OVERSAMPLE
    img = tile(size)
    draw = ImageDraw.Draw(img)
    arcs = 1 if px <= 20 else 2
    cx, cy = size * 0.5, size * 0.5         # the dot, centred
    dot = size * (0.11 if px <= 20 else 0.085)
    draw.ellipse((cx - dot, cy - dot, cx + dot, cy + dot), fill=WHITE)
    width = size * (0.10 if px <= 20 else 0.07)
    span = size * (0.34 if px <= 20 else 0.38)
    for i in range(arcs):
        r = dot + (span - dot) * (i + 1) / arcs
        box = (cx - r, cy - r, cx + r, cy + r)
        for start in (-45, 135):            # heard on both sides
            draw.arc(box, start=start, end=start + 90, fill=WHITE, width=max(round(width), 1))
    return img.resize((px, px), Image.Resampling.LANCZOS)


def main() -> None:
    out = Path(__file__).resolve().parent.parent / "src" / "gui" / "MdnsListener.ico"
    images = [render(s) for s in SIZES]
    largest = images[-1]
    largest.save(out, format="ICO", sizes=[(s, s) for s in SIZES], append_images=images[:-1])
    assert out.stat().st_size > 0
    print(f"wrote {out} ({out.stat().st_size} bytes, {len(SIZES)} sizes)")


if __name__ == "__main__":
    main()
