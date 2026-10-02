# Contributing to PolyglotBugHunter-X

First: thank you. 🕷️ Most of this project is people who found a bug class and
decided the scanner should know about it too.

## The one hard rule

**Payloads must be non-destructive.** CI runs
`is_forbidden_payload()` over every payload in `payloads.py`, and a PR that adds
`DROP TABLE`, `sleep()`, a reverse shell, or a mass-delete will be closed.

The list is in `src/polyglot_bug_hunter/safety.py::FORBIDDEN_PAYLOAD_SUBSTRINGS`.
If your payload needs a technique that looks scary but isn't (a subquery, an
error-based read, a polyglot escape), just explain it in the PR — reviewers read
every one.

What we *do* want: things that make a target **answer differently**, not things
that make it fall over.

## Setup

```bash
git clone https://github.com/Kicaulah/polyglot-bughunter-x
cd polyglot-bughunter-x
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q
```

Everything optional is optional. The core is stdlib-only and the test suite runs
with nothing but pytest installed.

## Adding a bug class

1. Add payloads to the right bucket in `src/polyglot_bug_hunter/payloads.py`.
   Each `Payload` needs: `value`, `label`, `vuln`, `cwe`, `owasp`, `confidence`,
   a `cvss` tuple, and a one-line `note` saying what signal it should produce.
2. Add detection to `scanner/text.py::classify`. The verdict has to be
   *differential* — compare against the captured baseline, don't just check
   whether your string came back.
3. Add an endpoint to `demo_target.py` that reproduces the bug class. This is the
   part people skip, and it's the part that makes the test suite meaningful.
4. Add a test that asserts the verdict on the demo endpoint, **and** a test that
   asserts a clean endpoint stays clean. Both directions matter; a scanner that
   reports everything is noise.
5. If it's a new class, add a route in `payloads.ROUTES` so the parameter-name
   router picks it up.

## Adding a language

`locales/en.json` is the master. Copy it to `locales/<code>.json`, translate the
values, leave the keys alone, and set `_meta`.

```bash
python -c "import json,pathlib; d=json.loads(pathlib.Path('locales/en.json').read_text()); print(len([k for k in d if not k.startswith('_meta')]))"
```

Tests enforce: same key set, no blanks, placeholders identical to English, and
that the translation actually differs from English (a copy-paste "translation"
gets caught). Translate the language's *name into itself* — 日本語 stays 日本語.

## Style

* Comments explain **why**, not what. `# loop until the queue is empty` is noise.
  `# first occurrence wins, later duplicates drop` is useful.
* Public functions get type hints. `from __future__ import annotations` is already
  in every module.
* Nothing prints; use `logging`.
* Keep lines under ~100 chars. `ruff check .` should be clean.
* Comments and code can be casual — this isn't a formal codebase. But keep it
  readable by someone who didn't write it.

## Before you open a PR

```bash
python -m pytest -q                     # 325 tests
ruff check .                            # if you have it
python tools/build_dataset.py           # regenerate the dataset
python tools/build_space.py             # re-vendor the Space copy
python tools/build_notebook.py          # regenerate the notebook
```

If you touched `src/`, re-run `python tools/build_space.py` and commit
`hf_space/` — the Space ships a vendored copy of the library and drift between
the two is a real class of bug.

## Reporting a security issue in *this* project

Not in the payload path — in the tool itself. See [SECURITY.md](SECURITY.md).

## Code of conduct

Be decent. Assume the other person is trying to help. Critique the code, not the
person. That's it.
