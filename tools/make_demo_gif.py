#!/usr/bin/env python3
"""Record the demo and build an animated GIF, no ffmpeg required.

docs/GROWTH.md tells you to make a demo GIF. It also tells you the command
involves ffmpeg and agg, which is two more installs before you have an asset.
This does it with what is already here: playwright drives the real page,
each frame is captured as PNG, and the GIF is encoded in pure Python.

    python tools/make_demo_gif.py
    python tools/make_demo_gif.py --live        # record the deployed Space

Output: assets/demo.gif (used by the READMEs) and assets/demo-frames/.
"""

from __future__ import annotations

import argparse
import functools
import zlib
import http.server
import socketserver
import struct
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPACE = ROOT / "hf_static_space"
ASSETS = ROOT / "assets"
FRAMES = ASSETS / "demo-frames"

WIDTH = 900          # keep it small: HF READMEs are not a video host
FPS = 12
HOLD = 3             # extra identical frames at the end so it lands


def serve(directory: Path):
    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler, directory=str(directory))
    handler.log_message = lambda *a, **k: None

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    httpd = Server(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


# ---------------------------------------------------------------- PNG decode
# minimal, because we only need to read our own screenshots back


def decode_png(data: bytes) -> tuple[int, int, bytes]:
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a png")
    pos, w, h, depth, color, idat = 8, 0, 0, 0, 0, bytearray()
    while pos + 8 <= len(data):
        ln = struct.unpack(">I", data[pos: pos + 4])[0]
        kind = data[pos + 4: pos + 8]
        body = data[pos + 8: pos + 8 + ln]
        if kind == b"IHDR":
            w, h, depth, color = struct.unpack(">IIBB", body[:10])
        elif kind == b"IDAT":
            idat += body
        elif kind == b"IEND":
            break
        pos += 12 + ln
    if depth != 8 or color not in (0, 2, 4, 6):
        raise ValueError(f"unsupported png depth={depth} color={color}")
    channels = {0: 1, 2: 3, 4: 2, 6: 4}[color]
    raw = zlib.decompress(bytes(idat))
    stride = w * channels
    out = bytearray(w * h * 3)
    prev = bytearray(stride)
    idx = 0
    for y in range(h):
        ft = raw[idx]
        idx += 1
        line = bytearray(raw[idx: idx + stride])
        idx += stride
        if ft == 1:
            for i in range(channels, stride):
                line[i] = (line[i] + line[i - channels]) & 0xFF
        elif ft == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ft == 3:
            for i in range(stride):
                left = line[i - channels] if i >= channels else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ft == 4:
            for i in range(stride):
                a = line[i - channels] if i >= channels else 0
                b = prev[i]
                c = prev[i - channels] if i >= channels else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 0xFF
        for x in range(w):
            i = x * channels
            if channels in (1, 2):
                v = line[i]
                o = (y * w + x) * 3
                out[o] = out[o + 1] = out[o + 2] = v
            else:
                o = (y * w + x) * 3
                out[o] = line[i]
                out[o + 1] = line[i + 1]
                out[o + 2] = line[i + 2]
        prev = line
    return w, h, bytes(out)


# ---------------------------------------------------------------- GIF encode
# LZW as specified by GIF89a, written out longhand so there is no dependency


def _lzw_encode(indices: bytes, min_code_size: int) -> bytes:
    clear = 1 << min_code_size
    end = clear + 1
    code_size = min_code_size + 1
    table: dict[tuple[int, ...], int] = {}
    next_code = end + 1

    def reset() -> None:
        nonlocal table, next_code, code_size
        table = {(i,): i for i in range(clear)}
        next_code = end + 1
        code_size = min_code_size + 1

    reset()
    bits: list[int] = []
    acc = 0
    nbits = 0
    out = bytearray()

    def emit(code: int, size: int) -> None:
        nonlocal acc, nbits
        acc |= code << nbits
        nbits += size
        while nbits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            nbits -= 8

    emit(clear, code_size)
    cur: tuple[int, ...] = ()
    for byte in indices:
        nxt = cur + (byte,)
        if nxt in table:
            cur = nxt
            continue
        emit(table[cur], code_size)
        if next_code < 4096:
            table[nxt] = next_code
            next_code += 1
            if next_code - 1 == (1 << code_size) and code_size < 12:
                code_size += 1
        else:
            emit(clear, code_size)
            reset()
        cur = (byte,)
    if cur:
        emit(table[cur], code_size)
    emit(end, code_size)
    if nbits:
        out.append(acc & 0xFF)
    return bytes(out)


def _blocks(data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 255):
        chunk = data[i: i + 255]
        out.append(len(chunk))
        out += chunk
    out.append(0)
    return bytes(out)


def write_gif(path: Path, frames: list[tuple[bytes, int]], w: int, h: int,
              palette: bytes, delay_cs: int) -> None:
    """frames: [(rgb pixel bytes, delay in centiseconds)]"""
    out = bytearray(b"GIF89a")
    out += struct.pack("<HHBBB", w, h, 0xF7, 0, 0)   # 256-colour global table
    out += palette
    out += b"\x21\xFF\x0BNETSCAPE2.0\x03\x01\x00\x00\x00"  # loop forever
    for pixels, delay in frames:
        out += b"\x21\xF9\x04\x00" + struct.pack("<H", delay) + b"\x00\x00"
        out += b"\x2C" + struct.pack("<HHHHB", 0, 0, w, h, 0)
        out += bytes([8])
        out += _blocks(_lzw_encode(_quantise(pixels), 8))
    out += b"\x3B"
    path.write_bytes(bytes(out))


def _quantise(pixels: bytes) -> bytes:
    idx = bytearray(len(pixels) // 3)
    for i in range(0, len(pixels), 3):
        idx[i // 3] = _rgb_to_index(pixels[i], pixels[i + 1], pixels[i + 2])
    return bytes(idx)


# 3-3-2 bits per pixel: 8 levels of red, 8 of green, 4 of blue. 256 entries,
# and it packs into a single byte, which matters when every frame is 900x620.
def _rgb_to_index(r: int, g: int, b: int) -> int:
    return ((r >> 5) << 5) | ((g >> 5) << 2) | (b >> 6)


def _index_to_rgb(idx: int) -> tuple[int, int, int]:
    return (
        ((idx >> 5) & 0x07) * 255 // 7,
        ((idx >> 2) & 0x07) * 255 // 7,
        (idx & 0x03) * 255 // 3,
    )


def build_palette(frames: list[bytes]) -> bytes:
    """One shared 256-colour table built from every frame, so colours stay stable
    between frames. Without this a shared palette would still dither."""
    counts: dict[int, int] = {}
    for pixels in frames:
        for i in range(0, len(pixels), 3):
            key = _rgb_to_index(pixels[i], pixels[i + 1], pixels[i + 2])
            counts[key] = counts.get(key, 0) + 1
    top = sorted(counts, key=lambda k: -counts[k])[:256]
    while len(top) < 256:
        top.append(0)
    pal = bytearray()
    for key in top:
        pal += bytes(_index_to_rgb(key))
    return bytes(pal[:768])


# ---------------------------------------------------------------- record


def record(url: str, out_dir: Path) -> int:
    from playwright.sync_api import sync_playwright

    out_dir.mkdir(parents=True, exist_ok=True)
    frames: list[tuple[bytes, int]] = []
    pixels_seen: list[bytes] = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        page = browser.new_page(viewport={"width": WIDTH, "height": 620},
                                device_scale_factor=1)

        def shot(name: str, hold: int = 2) -> None:
            raw = page.screenshot(type="png")
            (out_dir / f"{name}.png").write_bytes(raw)
            w, h, px = decode_png(raw)
            for _ in range(hold):
                frames.append((px, int(100 / FPS)))
                pixels_seen.append(px)
            print(f"  captured {name}  ({w}x{h})")

        print(f"recording {url}")
        page.goto(url, wait_until="networkidle")
        page.wait_for_timeout(1200)
        shot("01-landing", hold=8)

        # the click that matters
        page.click("#run-demo")
        page.wait_for_timeout(500)
        shot("02-scanning", hold=4)
        page.wait_for_selector("#results:not([hidden])", timeout=45000)
        page.wait_for_timeout(600)
        shot("03-report", hold=10)

        # scroll to the findings so the money shot is in frame
        page.evaluate("document.querySelector('#findings').scrollIntoView()")
        page.wait_for_timeout(400)
        shot("04-findings", hold=10)

        # a single finding expanded
        try:
            page.locator("#findings .card details summary").first.click()
            page.wait_for_timeout(350)
            shot("05-evidence", hold=10)
        except Exception:
            pass

        # the report tab
        page.evaluate("window.scrollTo(0,0)")
        page.click('.tab[data-tab="report"]')
        page.wait_for_timeout(500)
        shot("06-report-tab", hold=10)

        # the payload lab + canary
        page.click('.tab[data-tab="multi"]')
        page.click('.subtab[data-sub="text"]')
        page.fill("#payload", "{{7*7}}")
        page.click("#analyze")
        page.wait_for_timeout(450)
        shot("07-payload-lab", hold=10)

        page.click('.subtab[data-sub="image"]')
        page.click("#make-canary")
        page.wait_for_timeout(700)
        shot("08-canary", hold=10)

        # a non-latin language, because 12 locales is a feature worth showing
        page.click('.tab[data-tab="scan"]')
        page.select_option("#lang", "ja")
        page.wait_for_timeout(900)
        shot("09-japanese", hold=8)
        page.select_option("#lang", "ar")
        page.wait_for_timeout(900)
        shot("10-arabic-rtl", hold=10)

        browser.close()

    # hold the last frame so the loop does not snap back
    for _ in range(HOLD * 6):
        frames.append(frames[-1])

    palette = build_palette(pixels_seen)
    gif = ROOT / "assets" / "demo.gif"
    ASSETS.mkdir(parents=True, exist_ok=True)
    write_gif(gif, frames, WIDTH, frames and 620 or 620, palette, int(100 / FPS))
    size = gif.stat().st_size
    print(f"\n  frames  : {len(frames)}")
    print(f"  written : {gif}  ({size / 1024:.0f} KB)")
    if size > 3_500_000:
        print("  note    : over 3MB. re-run with fewer frames or WIDTH=760")
    return 0


def main() -> int:

    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true",
                    help="record the deployed Space instead of a local server")
    args = ap.parse_args()

    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except Exception:
        print("playwright not installed: pip install playwright && playwright install chromium")
        return 1

    if args.live:
        url = "https://kicaulah-polyglot-bughunter-x-static.static.hf.space/index.html"
        return record(url, FRAMES)

    httpd, port = serve(SPACE)
    try:
        return record(f"http://127.0.0.1:{port}/index.html", FRAMES)
    finally:
        httpd.shutdown()


if __name__ == "__main__":
    sys.exit(main())