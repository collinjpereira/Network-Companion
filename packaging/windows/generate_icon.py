"""
Generates packaging/windows/icon.ico, the app icon used by the PyInstaller
build (network-companion.spec) and the Inno Setup installer (installer.iss).

A small network-topology glyph (matches the web UI's dark theme + signal
cyan accent from static/style.css) rendered at the standard Windows icon
sizes. Re-run this only if the icon design needs to change:

    python packaging/windows/generate_icon.py
"""

import os

from PIL import Image, ImageDraw, ImageFilter

HERE = os.path.dirname(os.path.abspath(__file__))

BG_TOP = (16, 22, 35)      # matches --surface
BG_BOTTOM = (10, 14, 22)   # matches --bg
ACCENT = (61, 214, 208)    # matches --accent (signal cyan)
ACCENT_DIM = (31, 111, 108)  # matches --accent-dim


def _rounded_square_bg(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    for y in range(size):
        t = y / max(size - 1, 1)
        r = int(BG_TOP[0] + (BG_BOTTOM[0] - BG_TOP[0]) * t)
        g = int(BG_TOP[1] + (BG_BOTTOM[1] - BG_TOP[1]) * t)
        b = int(BG_TOP[2] + (BG_BOTTOM[2] - BG_TOP[2]) * t)
        ImageDraw.Draw(img).line([(0, y), (size, y)], fill=(r, g, b, 255))

    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [0, 0, size - 1, size - 1], radius=int(size * 0.22), fill=255)
    img.putalpha(mask)
    return img


def _draw_network_glyph(size: int) -> Image.Image:
    """Central node with three satellite nodes, connected by lines --
    a simple network-topology glyph."""
    glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    art = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    d = ImageDraw.Draw(art)

    cx, cy = size * 0.5, size * 0.5
    center = (cx, cy)
    satellites = [
        (size * 0.5, size * 0.20),
        (size * 0.20, size * 0.68),
        (size * 0.80, size * 0.68),
    ]

    line_w = max(1, int(size * 0.045))
    for sx, sy in satellites:
        gd.line([center, (sx, sy)], fill=(*ACCENT, 130), width=line_w * 3)
        d.line([center, (sx, sy)], fill=(*ACCENT, 235), width=line_w)

    r_center = size * 0.11
    r_sat = size * 0.075

    gd.ellipse([cx - r_center * 2, cy - r_center * 2,
                cx + r_center * 2, cy + r_center * 2], fill=(*ACCENT, 90))
    for sx, sy in satellites:
        gd.ellipse([sx - r_sat * 2, sy - r_sat * 2,
                    sx + r_sat * 2, sy + r_sat * 2], fill=(*ACCENT, 90))

    glow = glow.filter(ImageFilter.GaussianBlur(radius=size * 0.03))

    d.ellipse([cx - r_center, cy - r_center, cx + r_center, cy + r_center],
              fill=(*ACCENT, 255), outline=(*BG_BOTTOM, 255), width=max(1, int(size * 0.012)))
    for sx, sy in satellites:
        d.ellipse([sx - r_sat, sy - r_sat, sx + r_sat, sy + r_sat],
                   fill=(*ACCENT_DIM, 255), outline=(*ACCENT, 255), width=max(1, int(size * 0.012)))

    out = Image.alpha_composite(glow, art)
    return out


def build_icon(size: int) -> Image.Image:
    bg = _rounded_square_bg(size)
    glyph = _draw_network_glyph(size)
    return Image.alpha_composite(bg, glyph)


def main():
    sizes = [16, 24, 32, 48, 64, 128, 256]
    base = build_icon(256)
    # Pre-render each size ourselves (LANCZOS downscaling looks much
    # cleaner than ICO's default resampling at 16/24px) and hand Pillow
    # the full set as separate frames -- passing sizes= to a single
    # already-downscaled image silently drops every size but that one.
    imgs = [base.resize((s, s), Image.LANCZOS) for s in sizes]
    out_path = os.path.join(HERE, "icon.ico")
    base.save(out_path, format="ICO", sizes=[(s, s) for s in sizes],
              append_images=imgs)
    print(f"Wrote {out_path}")

    png_path = os.path.join(HERE, "icon.png")
    base.save(png_path, format="PNG")
    print(f"Wrote {png_path}")


if __name__ == "__main__":
    main()
