#!/usr/bin/env python3
"""One command to try PolyglotBugHunter-X. No install, no venv, no setup.

    ./run.py                 the offline demo + a written report
    ./run.py demo            the same
    ./run.py serve           the 4-tab UI on http://127.0.0.1:7860
    ./run.py static          the Static Space UI on http://127.0.0.1:8000
    ./run.py scan URL ...    anything else, forwarded to the CLI

This is the entry point for someone who just cloned the repo. It puts src/ on
the path itself, so it works in a bare checkout with nothing installed.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"

BOLD, DIM, GREEN, YELLOW, CYAN = "1", "2", "32", "33", "36"
TTY = sys.stdout.isatty()


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if TTY else text


def local_app() -> bool:
    return SRC.is_dir()


def show_menu() -> None:
    print(f"""
{c('PolyglotBugHunter-X', BOLD)}  {c('multimodal web bug hunter', DIM)}

  {c('1', CYAN)}  demo          scan the bundled target, fully offline
  {c('2', CYAN)}  scan          scan a target you own or have permission for
  {c('3', CYAN)}  serve         the 4-tab Gradio UI on 127.0.0.1:7860
  {c('4', CYAN)}  static        the Static Space UI on 127.0.0.1:8000
  {c('5', CYAN)}  canary        write the visual prompt-injection canary
  {c('6', CYAN)}  audio         write the adversarial audio suite
  {c('7', CYAN)}  capabilities  what is installed here

  {c('start with 1. it needs no network and no authorization.', DIM)}
""")


def run_static(port: int = 8000) -> int:
    """Serve the Static Space. Needs nothing at all, not even Python packages."""
    folder = ROOT / "hf_static_space"
    if not folder.is_dir():
        print(f"error: {folder} is missing from this checkout", file=sys.stderr)
        return 2

    print(c(f"static UI on http://127.0.0.1:{port}/", BOLD))
    print(c("  this is the exact app that runs on the Hugging Face Static Space.", DIM))
    print(c("  the demo and payload lab work offline. scanning a real target", DIM))
    print(c("  needs the CLI, because a browser page cannot make server requests.", DIM))
    print(c("  ctrl-c to stop", DIM))
    print()

    try:
        import http.server
        import socketserver
    except Exception as exc:  # pragma: no cover
        print(f"error: {exc}", file=sys.stderr)
        return 2

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(folder), **kw)

        def end_headers(self):
            # no cache, so an edit shows up on reload
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def log_message(self, *a):  # quiet
            pass

    try:
        with socketserver.TCPServer(("127.0.0.1", port), Handler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    except OSError as exc:
        print(f"error: cannot bind 127.0.0.1:{port} - {exc}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str]) -> int:
    args = argv[1:]
    if not args:
        show_menu()
        try:
            choice = input(c("pick a number (or 'q' to quit): ", BOLD)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choice.lower() in ("q", "quit", "exit", ""):
            return 0
        args = {
            "1": ["demo"], "2": ["scan"], "3": ["serve"], "4": ["static"],
            "5": ["canary"], "6": ["audio"], "7": ["capabilities"],
        }.get(choice, [])
        if not args:
            print(f"error: {choice!r} is not on the menu", file=sys.stderr)
            return 2

    if args[0] == "static":
        port = 8000
        if "--port" in args:
            port = int(args[args.index("--port") + 1])
        return run_static(port)

    if not local_app():
        print(f"error: {SRC} is missing, this does not look like the repo", file=sys.stderr)
        return 2

    # everything else is the real CLI
    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))
    try:
        from polyglot_bug_hunter.cli import main as cli_main
    except Exception as exc:
        print(f"error: cannot import the package: {exc}", file=sys.stderr)
        print("  try: pip install -e .", file=sys.stderr)
        return 2

    if args[0] in ("demo", "canary", "audio", "capabilities", "payloads", "targets"):
        banner = f"{c('polyglot-bughunter-x', GREEN)} {c('running offline, no authorization needed', DIM)}"
        print(f"{banner}\n")
    return int(cli_main(args) or 0)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
