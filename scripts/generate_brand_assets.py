#!/usr/bin/env python3
"""Generate SentinelVAPT's brand assets from one vector description.

Every icon the application ships — the macOS .icns, the Windows .ico, the Linux
PNGs and the two NSIS installer bitmaps — is drawn here rather than checked in
as an opaque binary, so the mark can be revised in one place and every size
stays consistent. Re-run with:

    python3 scripts/generate_brand_assets.py

The mark: a shield in a cyan-to-blue gradient on a deep navy field, with a
targeting reticle cut out of it. Shield for defence, reticle for the locating
this tool actually does — not a keyhole or a tick, which are on half the
security icons in existence and say nothing about the product. It is drawn as
solid shapes with wide strokes because 16px and 32px are where an icon is
usually seen, and fine detail simply disappears there.

Everything is rendered at 8x and downsampled with LANCZOS, which is what keeps
the diagonal shield edge clean without an SVG rasteriser being installed.
"""

import os
from PIL import Image, ImageDraw, ImageFilter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ICONS = os.path.join(ROOT, "apps", "desktop", "src-tauri", "icons")
INSTALLER = os.path.join(ROOT, "apps", "desktop", "src-tauri", "installer")
ASSETS = os.path.join(ROOT, "apps", "desktop", "src", "assets")

# ── Palette ──────────────────────────────────────────────────────────────────
# Matches the application's own --cyan and the reports' --brand, so the icon,
# the window chrome and the PDF read as one product.
NAVY_DEEP = (8, 14, 28)
NAVY = (13, 22, 42)
NAVY_LIGHT = (22, 36, 64)
CYAN = (34, 211, 238)
CYAN_DEEP = (14, 165, 200)
BLUE = (37, 99, 235)
WHITE = (241, 249, 255)
AMBER = (251, 191, 36)

SS = 8  # supersampling factor


def lerp(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def vertical_gradient(size, top, bottom):
    """A one-pixel-wide gradient stretched to `size`, cheaper than per-row draw."""
    strip = Image.new("RGB", (1, size[1]))
    px = strip.load()
    for y in range(size[1]):
        px[0, y] = lerp(top, bottom, y / max(1, size[1] - 1))
    return strip.resize(size, Image.Resampling.BILINEAR)


def shield_polygon(cx, cy, w, h, steps=48):
    """A shield: flat top, straight shoulders, flanks curving in to a point.

    The flanks are sampled from a quadratic curve rather than drawn as one
    straight line, because a purely angular shield reads as a home-plate
    pentagon. The top stays flat and the shoulders stay square — those are the
    features that survive downsampling to 16px, where the curve itself is only
    a couple of pixels of shaping.
    """
    half = w / 2
    top = cy - h / 2
    tip = cy + h / 2
    shoulder = top + h * 0.34  # where the flank starts bending inward

    def flank(sign):
        """Quadratic from the shoulder to the tip, bulging outward."""
        start = (cx + sign * half, shoulder)
        control = (cx + sign * half * 0.98, top + h * 0.80)
        end = (cx, tip)
        points = []
        for i in range(1, steps + 1):
            t = i / steps
            u = 1 - t
            points.append((
                u * u * start[0] + 2 * u * t * control[0] + t * t * end[0],
                u * u * start[1] + 2 * u * t * control[1] + t * t * end[1],
            ))
        return points

    return (
        [(cx - half, top), (cx + half, top), (cx + half, shoulder)]
        + flank(1)
        + list(reversed(flank(-1)))
        + [(cx - half, shoulder)]
    )


def draw_mark(size, *, background=True, corner_ratio=0.225, padding_ratio=0.16):
    """Render the mark at `size` pixels square."""
    s = size * SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))

    if background:
        # Rounded-square field with a soft radial lift behind the shield, so the
        # icon has depth on both light and dark desktop wallpapers.
        field = Image.new("RGB", (s, s), NAVY_DEEP)
        glow = Image.new("L", (s, s), 0)
        ImageDraw.Draw(glow).ellipse(
            [s * 0.10, s * 0.02, s * 0.90, s * 0.74], fill=170
        )
        glow = glow.filter(ImageFilter.GaussianBlur(s * 0.14))
        field = Image.composite(Image.new("RGB", (s, s), NAVY_LIGHT), field, glow)

        mask = Image.new("L", (s, s), 0)
        ImageDraw.Draw(mask).rounded_rectangle(
            [0, 0, s - 1, s - 1], radius=s * corner_ratio, fill=255
        )
        img.paste(field, (0, 0), mask)

    pad = s * padding_ratio
    cx, cy = s / 2, s / 2
    w = (s - pad * 2) * 0.94
    h = (s - pad * 2) * 1.06

    # ── Shield body, filled with the cyan→blue gradient ──────────────────────
    shield = shield_polygon(cx, cy, w, h)
    shield_mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(shield_mask).polygon(shield, fill=255)
    grad = vertical_gradient((s, s), CYAN, BLUE)
    img.paste(grad, (0, 0), shield_mask)

    # ── Targeting reticle, cut out of the shield ────────────────────────────
    # Drawn onto a separate layer then masked to the shield, so nothing spills
    # past the silhouette however wide the strokes get.
    #
    # A reticle rather than a keyhole or a tick: both of those are on half the
    # security icons in existence, and neither says anything about what this
    # tool does. A reticle says "locate", which is the job.
    cut = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    cd = ImageDraw.Draw(cut)

    ring_cx = cx
    ring_cy = cy - h * 0.055  # optically centred: the shield's mass sits high
    ink = NAVY_DEEP + (255,)
    stroke = max(2, int(s * 0.042))

    # The ring, broken at the four diagonals so it reads as an instrument
    # rather than as a plain circle.
    r = w * 0.235
    for start in (18, 108, 198, 288):
        cd.arc(
            [ring_cx - r, ring_cy - r, ring_cx + r, ring_cy + r],
            start=start,
            end=start + 54,
            fill=ink,
            width=stroke,
        )

    # Crosshair ticks, crossing the ring and extending a little beyond it.
    inner = r * 0.46
    outer = r * 1.36
    for dx, dy in ((0, -1), (0, 1), (-1, 0), (1, 0)):
        cd.line(
            [
                (ring_cx + dx * inner, ring_cy + dy * inner),
                (ring_cx + dx * outer, ring_cy + dy * outer),
            ],
            fill=ink,
            width=stroke,
        )

    # Locked on: a solid dot at the centre.
    dot = w * 0.055
    cd.ellipse(
        [ring_cx - dot, ring_cy - dot, ring_cx + dot, ring_cy + dot],
        fill=ink,
    )

    cut_masked = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    cut_masked.paste(cut, (0, 0), shield_mask)
    img = Image.alpha_composite(img, cut_masked)

    # ── Highlight along the shield's top-left edge ───────────────────────────
    edge = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    ImageDraw.Draw(edge).line(
        [shield[0], shield[1]], fill=WHITE + (165,), width=max(2, int(s * 0.024))
    )
    edge_masked = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    edge_masked.paste(edge, (0, 0), shield_mask)
    img = Image.alpha_composite(img, edge_masked)

    return img.resize((size, size), Image.Resampling.LANCZOS)


def wordmark(width, height, *, dark=True):
    """Horizontal lockup: the mark beside the product name."""
    s_w, s_h = width * 4, height * 4
    bg = NAVY_DEEP if dark else WHITE
    img = Image.new("RGB", (s_w, s_h), bg)

    if dark:
        glow = Image.new("L", (s_w, s_h), 0)
        ImageDraw.Draw(glow).ellipse(
            [-s_w * 0.1, s_h * 0.2, s_w * 0.75, s_h * 1.6], fill=120
        )
        glow = glow.filter(ImageFilter.GaussianBlur(s_h * 0.30))
        img = Image.composite(Image.new("RGB", (s_w, s_h), NAVY_LIGHT), img, glow)

    mark_size = int(s_h * 0.72)
    mark = draw_mark(mark_size, background=False, padding_ratio=0.02)
    img.paste(mark, (int(s_h * 0.20), int((s_h - mark_size) / 2)), mark)

    d = ImageDraw.Draw(img)
    text_x = int(s_h * 0.20) + mark_size + int(s_h * 0.20)
    ink = WHITE if dark else NAVY_DEEP

    # Drawn with the default bitmap font scaled up: the assets must build on a
    # machine with no particular font installed, and a missing TrueType file
    # would otherwise fail the release build rather than the developer's laptop.
    label = Image.new("RGBA", (s_w, s_h), (0, 0, 0, 0))
    ld = ImageDraw.Draw(label)
    ld.text((0, 0), "SENTINEL", fill=ink + (255,))
    ld.text((0, 12), "V A P T", fill=CYAN + (255,))
    bbox = label.getbbox()
    if bbox:
        cropped = label.crop(bbox)
        scale = min(
            (s_w - text_x - s_h * 0.2) / cropped.width,
            (s_h * 0.52) / cropped.height,
        )
        cropped = cropped.resize(
            (max(1, int(cropped.width * scale)), max(1, int(cropped.height * scale))),
            Image.Resampling.LANCZOS,
        )
        img.paste(cropped, (text_x, int((s_h - cropped.height) / 2)), cropped)

    del d
    return img.resize((width, height), Image.Resampling.LANCZOS)


def sidebar(width, height):
    """The tall NSIS welcome panel."""
    s_w, s_h = width * 4, height * 4
    img = vertical_gradient((s_w, s_h), NAVY_LIGHT, NAVY_DEEP)

    glow = Image.new("L", (s_w, s_h), 0)
    ImageDraw.Draw(glow).ellipse(
        [-s_w * 0.4, -s_h * 0.1, s_w * 1.4, s_h * 0.75], fill=140
    )
    glow = glow.filter(ImageFilter.GaussianBlur(s_w * 0.30))
    img = Image.composite(Image.new("RGB", (s_w, s_h), (28, 48, 86)), img, glow)

    mark_size = int(s_w * 0.62)
    mark = draw_mark(mark_size, background=False, padding_ratio=0.02)
    img.paste(mark, (int((s_w - mark_size) / 2), int(s_h * 0.16)), mark)

    # A faint scan grid in the lower third, echoing the radar in the mark.
    d = ImageDraw.Draw(img, "RGBA")
    for i in range(14):
        y = int(s_h * 0.62 + i * s_h * 0.026)
        d.line([(0, y), (s_w, y)], fill=CYAN + (16,), width=max(1, s_w // 220))

    return img.resize((width, height), Image.Resampling.LANCZOS)


def main():
    os.makedirs(ICONS, exist_ok=True)
    os.makedirs(INSTALLER, exist_ok=True)
    written = []

    # ── Application icons ────────────────────────────────────────────────────
    for name, size in (("32x32.png", 32), ("128x128.png", 128), ("128x128@2x.png", 256)):
        path = os.path.join(ICONS, name)
        draw_mark(size).save(path)
        written.append(path)

    # Windows .ico carries every size the shell asks for; leaving one out makes
    # Windows scale a neighbour and the taskbar icon looks soft.
    ico_sizes = [16, 24, 32, 48, 64, 128, 256]
    ico_path = os.path.join(ICONS, "icon.ico")
    draw_mark(256).save(ico_path, sizes=[(s, s) for s in ico_sizes])
    written.append(ico_path)

    # macOS .icns via iconutil, which needs a populated .iconset directory.
    iconset = os.path.join(ICONS, "icon.iconset")
    os.makedirs(iconset, exist_ok=True)
    for size in (16, 32, 64, 128, 256, 512, 1024):
        draw_mark(size).save(os.path.join(iconset, f"icon_{size}x{size}.png"))
        if size <= 512:
            draw_mark(size * 2).save(os.path.join(iconset, f"icon_{size}x{size}@2x.png"))
    icns_path = os.path.join(ICONS, "icon.icns")
    if os.system(f'iconutil -c icns "{iconset}" -o "{icns_path}"') == 0:
        written.append(icns_path)
    else:
        # Not fatal off macOS: the existing .icns stays, and the Linux/Windows
        # bundles do not read it.
        print("note: iconutil unavailable, icon.icns left unchanged")
    for f in os.listdir(iconset):
        os.remove(os.path.join(iconset, f))
    os.rmdir(iconset)

    # ── NSIS installer artwork (BMP is the only format NSIS accepts) ─────────
    header = os.path.join(INSTALLER, "header.bmp")
    wordmark(150, 57).save(header)
    written.append(header)

    side = os.path.join(INSTALLER, "sidebar.bmp")
    sidebar(164, 314).save(side)
    written.append(side)

    # ── In-app artwork ───────────────────────────────────────────────────────
    os.makedirs(ASSETS, exist_ok=True)
    hero = os.path.join(ASSETS, "hero.png")
    draw_mark(343, corner_ratio=0.22).resize((343, 361)).save(hero)
    written.append(hero)

    for path in written:
        print(f"  {os.path.relpath(path, ROOT)}  ({os.path.getsize(path) / 1024:.1f} KB)")


if __name__ == "__main__":
    main()
