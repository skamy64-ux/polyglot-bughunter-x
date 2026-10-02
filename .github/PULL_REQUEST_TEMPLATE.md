## What this changes

<!-- one line. if it fixes an issue, say "fixes #123" -->

## Why

<!-- the problem, not the diff -->

## Checklist

- [ ] `python -m pytest -q` passes
- [ ] `node tools/test_static_space.mjs` passes — the JS port still matches Python
- [ ] `node tools/test_static_app.mjs` passes
- [ ] `python tools/check_links.py` passes
- [ ] `ruff check src tests tools` is clean
- [ ] if you touched `src/`: `python tools/build_space.py` and `build_static_space.py` re-run, and the generated copies are committed

## If you added a payload

- [ ] it is non-destructive (no DROP/DELETE/sleep/system/rm -rf/fork bomb)
- [ ] it has a CWE, an OWASP mapping, a CVSS vector and a note saying what it proves
- [ ] the demo target reproduces the class, so the test suite can assert the verdict
- [ ] there is a test that the clean endpoint still comes back clean — both directions
