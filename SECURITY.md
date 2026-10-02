# Security Policy

## Reporting a vulnerability in PolyglotBugHunter-X

**Do not open a public issue.** Email `security@polyglot-bughunter-x.dev` (or use
GitHub's private vulnerability reporting if it's enabled).

Include: what you found, how to reproduce it, the version/commit, and what an
attacker could achieve. We'll acknowledge within 72 hours and aim to ship a fix
within 14 days.

### In scope

Anything in `src/polyglot_bug_hunter/` that lets a request reach a host the
operator didn't authorize, executes something destructive, bypasses the payload
gate, or lets a crafted response execute code in the operator's own machine.

Specifically interesting:
* a bypass of `safety.ScanPolicy.check_url` / `check_method` / `check_payload`
* DNS rebinding or TOCTOU in the IP classification
* a payload from the catalogue (or a community PR) that slips past
  `is_forbidden_payload`
* unsafe deserialisation in the report/store code
* path traversal in `output_dir` handling
* the bundled demo target binding somewhere other than loopback

### Out of scope

* The scanner being *able* to detect a vulnerability — that's the feature.
* Someone pointing it at a system they don't own. That's not a bug in this
  project, it's a legal matter for whoever pointed it.
* Denial of service against yourself by scanning your own server hard.
* Missing hardening on an install that has no authorization flag set.

## Threat model

What this tool is designed to defend against:

| Threat | Mitigation |
|---|---|
| Operator scans a host they don't own | `authorization_confirmed` gate; nothing is sent without it. The Space hard-codes it off. |
| Scanner used to probe internal networks | Loopback, RFC1918, link-local (incl. `169.254.169.254`), CGNAT, multicast, reserved all refused. DNS resolved by us to defeat rebinding. |
| Scanner used to hit cloud metadata for credentials | Link-local range refused; `file://` and `gopher://` refused. |
| Payload damages the target | Every payload passes `is_forbidden_payload()`; time-based SQLi is unimplemented by design. |
| Scanner used as a DoS weapon | Mandatory rate limit (5–120 req/min) and a hard total request budget. |
| A malicious PR adds a destructive payload | CI runs the gate over the whole catalogue; the list lives in code, not in a config file. |
| Crafted response attacks the *operator* (XXE, billion laughs, HTML injection into the report) | The HTML report escapes all finding text and is self-contained with no external assets; XML parsing is not used anywhere. |

Known limitations, stated plainly:

* **Time-based blind SQLi is not implemented.** `sleep()` and `benchmark()` are
  blocked, so blind SQLi will not be detected. This is a deliberate trade: a
  scanner that can hang a database can be used as a DoS tool.
* **No authentication support.** The scanner visits as an anonymous client.
  Findings behind a login (authenticated IDOR, horizontal privilege escalation)
  are out of reach until someone builds session handling, and shipping credential
  handling into a public Space would be a worse problem.
* **Static DOM analysis cannot prove exploitability.** `innerHTML`/`eval` sinks
  found by pattern matching are tagged `needs-manual-confirm` and may be false
  positives.
* **Race detection is probabilistic** and is reported at low confidence by design.
* **WAF evasion is not attempted.** A blocked probe is reported as `blocked`,
  never as `clean`, so you know coverage was lost rather than that you're safe.

## Responsible disclosure

This is a defensive tool. The people who benefit from it are the ones running the
scans. If you find a way to weaponise it, that's a bug in this repo and we'll fix
it. If you find a bug *in someone's website* using this tool, tell them privately
and give them reasonable time to fix it before disclosing. That's the whole
ethos of the project.
