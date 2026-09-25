"""Original data-only companion and inert preview documents. No generated scripts."""
from __future__ import annotations

import base64
import html
import struct
import zlib

from . import contracts as c
from .media import decoded_companion


def sample_companion() -> tuple[dict, bytes]:
    """Generate original two-frame geometry; no borrowed artwork or font assets."""
    width, height = 64, 32
    scanlines = bytearray()
    for y in range(height):
        scanlines.append(0)
        for x in range(width):
            local = x % 32
            disk = (local - 16) ** 2 + (y - 16) ** 2 < 12 ** 2
            eye = local in (12, 20) and (y == 13 or (x < 32 and y == 14))
            scanlines.extend((255, 255, 255, 255) if eye else
                             (42, 122, 142, 255) if disk else (0, 0, 0, 0))
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    data = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(scanlines), 9)) + chunk(b"IEND", b""))
    return {"name": "Integrity companion", "asset": "integrity-original.png", "asset_sha256": c.sha(data),
            "width": width, "height": height, "frames": [[0, 0, 32, 32], [32, 0, 32, 32]], "fps": 2}, data


def companion_page(manifest: dict, data: bytes) -> str:
    normalized, _ = decoded_companion(manifest, data)
    frames = manifest["frames"]
    c.require(all(f[2:] == frames[0][2:] for f in frames), "uniform_display_frames_required")
    width, height = frames[0][2:]
    positions = "".join(f"{i * 100 / len(frames):.6f}% {{background-position: -{f[0]}px -{f[1]}px;}}"
                        for i, f in enumerate(frames))
    image = base64.b64encode(normalized).decode("ascii")
    csp = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"
    return ('<!doctype html><html><head><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" content="' + html.escape(csp, quote=True) + '">'
        '<style>body{font:16px system-ui;padding:24px}.pet{'
        f'width:{width}px;height:{height}px;background-image:url(data:image/png;base64,{image});'
        f'animation:frames {len(frames)/manifest["fps"]:.6f}s steps(1,end) infinite;'
        'image-rendering:pixelated;transform:scale(3);transform-origin:top left;margin-bottom:80px}'
        '@keyframes frames{' + positions + '}'
        '@media(prefers-reduced-motion:reduce){.pet{animation:none}}</style></head><body>'
        '<h1>' + html.escape(manifest["name"]) + '</h1><div class="pet" role="img" '
        'aria-label="Original decorative companion"></div>'
        '<p>Candidate view. Animation is not a verified action outcome.</p></body></html>')


def preview_page(source: str) -> str:
    iframe = c.inert_preview(source)["payload"]["iframe_html"]
    return ('<!doctype html><html><head><meta charset="utf-8">'
            '<meta http-equiv="Content-Security-Policy" '
            'content="default-src &apos;none&apos;; frame-src &apos;self&apos;; '
            'style-src &apos;unsafe-inline&apos;; base-uri &apos;none&apos;">'
            '<title>Integrity inert preview</title></head><body>' + iframe + '</body></html>')
