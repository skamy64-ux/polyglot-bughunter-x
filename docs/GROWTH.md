# 🚀 Getting to 1K+ stars/downloads on Hugging Face

What actually moves the number, in the order it matters. Everything here is
either already done in this repo (✅) or something only you can do after
uploading (⬜).

---

## The one thing that matters most

**A visitor must get a result in under 10 seconds without installing anything.**

Everything else on this page is worth less than that. The "🚀 Scan Example"
button exists for exactly this reason: it boots a vulnerable app on localhost,
so there is no network dependency, no rate limit on third-party services, no
"add your API key first", and no way for a first-time visitor to bounce.

✅ Implemented. Verified: demo scan completes in **~8 seconds** on CPU.

---

## ⚠️ Read this first: HF now requires PRO for Gradio Spaces

As of this project's build, creating a **new** Gradio or Docker Space on a free
account returns `402 Payment Required`:

> Static Spaces are free for everyone, but hosting Gradio and Docker Spaces on
> free cpu-basic requires a PRO subscription.

This is an **account plan limit, not a code problem.** Verified: the API rejects
`create_repo(repo_type="space", space_sdk="gradio")` on a free account, while
`space_sdk="static"` succeeds immediately.

What that means in practice:

| | Gradio Space | Static Space |
|---|---|---|
| Cost | HF PRO, ~$9/mo | free |
| Cold start | 10–60s (gradio install) | instant |
| Scans real targets | ✅ yes | ❌ no server, so no |
| Screenshot proof | ✅ playwright | ❌ canvas only |
| Demo works offline | ✅ | ✅ |

So: the **Static Space** ships the demo, the payload lab, the canary generator
and the audio suite — everything that makes a visitor go "wait, it runs *in my
browser*?" The **Python package** does the real scanning. If you want the Gradio
Space scanning live targets, subscribe to PRO and `hf_space/` uploads as-is
(it is complete and tested — `tools/smoke_space.py` passes).

## ✅ Already done in this repo

### Make the Space instantly usable
- [x] One-click "🚀 Scan Example" with an offline target that always works
- [x] 4 tabs: Scan · Multimodal Input · Report · About
- [x] Progress indicator, never a traceback — Space errors are caught and shown
      as text, because an unhandled exception in a public Space looks broken
- [x] 4 downloadable report formats (`.md`, `.html`, `.json`, `.sarif`)
- [x] Works on the **free CPU tier**: `requirements.txt` is gradio-only, every
      heavy dependency is optional and commented out
- [x] Guarded `launch()` (`PBHX_NO_LAUNCH`) so the app is importable for tests

### Full YAML frontmatter on all three cards
- [x] **Space**: `title`, `emoji`, `colorFrom`, `colorTo`, `sdk`, `sdk_version`,
      `app_file`, `pinned: true`, `license`, `short_description`, `tags`
- [x] **Model**: 12 `language` codes, `license: mit`, `tags`,
      `pipeline_tag`, `library_name`, `inference: false`, `datasets`,
      `model-index`-adjacent links
- [x] **Dataset**: `language`, `license`, `task_categories`, `tags`,
      `size_categories`, per-config `data_files` for all four configs

### Cross-linking (internal HF SEO)
- [x] Space ↔ Model ↔ Dataset ↔ GitHub ↔ notebook, in all five places
- [x] README opens with "🔥 Try it now" pointing straight at the Space
- [x] Model card and dataset card both link to the Space
- [x] The Space's About tab links back out to all three

### Badges
- [x] HF Space · HF Model · HF Dataset · GitHub · License · Python version
- [x] `shields.io`-compatible alt text and colours that render on HF

### Trust and honesty
- [x] Legal notice in every README, in the Space UI, in every generated report
- [x] `SECURITY.md` with a real threat model, not a template
- [x] Limitations section that's honest about what the tool *cannot* do
- [x] "Not trained / no private data" stated plainly in the model card
- [x] Evaluation table with real numbers (0/5000 CVSS mismatches, 13/13 demo
      classes, 100% locale coverage)
- [x] Changelog in all three cards

### Community
- [x] Discussion + PR + issue links in all three cards and the Space UI
- [x] `CONTRIBUTING.md` with the one hard rule (payloads must be non-destructive)
- [x] `CHANGELOG.md` with an Unreleased section
- [x] Citation in BibTeX, `CITATION.cff`, and the model card

---

## ⬜ Your checklist after uploading

### Day 1 — the 60 minutes that matter
1. **Pin the Space** to your profile. `pinned: true` is in the frontmatter, but
   confirm it's set in the Space settings UI too.
2. **Run the demo yourself** in the live Space. Click every tab. If anything 500s,
   fix it before anyone else sees it.
3. **Post to X and LinkedIn** with a screen recording of the demo, not a
   screenshot. Motion beats stills.
4. **r/netsec, r/webdev, Hacker News** — lead with the *demo*, not the tool.
   "I built a scanner that sees, hears and reads websites" is a story;
   "here is my static analysis tool" is not.
5. **HF Discord** (`#show-and-tell`) and the **Spaces category**.

### Week 1 — keep the loop alive
- [ ] Reply to every Discussion/issue within 24h. Response rate is the single
      strongest signal that a repo is alive, and HF's algorithm notices.
- [ ] Ship something small every 2 weeks. HF boosts recently-updated repos, and
      "2 weeks of nothing" reads as abandoned. Ideas: one new payload class,
      one new language, a `--json` CI action, an OWASP ZAP import.
- [ ] Post each release to the Discussions tab as a changelog, not just GitHub.
- [ ] Add a real demo GIF to the READMEs (`assets/demo.gif`). Autoplay, under
      15s, under 3MB. Generate it with `asciinema` + `agg` or `ffmpeg` from one
      clean demo run.

### Week 2–4 — compound the reach
- [ ] Find 10 blogs/newsletters that cover web security or LLM security. Security
      newsletters want **tools + demos**, not papers. Offer the author a
      free-running instance.
- [ ] Cross-post to Reddit with genuinely different framing per subreddit.
      Copy-pasted posts get flagged; take the time to adapt.
- [ ] Submit to awesome-lists: `awesome-web-security`,
      `awesome-llm-security`, `awesome-python-security`. One PR each.
- [ ] Write one deep technical post (the differential-analysis design and the
      `replace_param` bug are both genuinely interesting stories). Dev.to and
      Medium syndicate; Hashnode and freeCodeCamp republish.

### The demo GIF
```bash
# record a clean demo run
asciinema rec demo.cast -c "python -c 'from polyglot_bug_hunter import Hunter; r=Hunter.demo(); [print(f\"{f.severity.value:8s} {f.cvss.score:4} {f.title}\") for f in r.sorted_findings()[:12]]'"
agg demo.cast assets/demo.gif --colors=16m --width 100
# compress it, HF READMEs should stay under a few MB
ffmpeg -i assets/demo.gif -vf "fps=12,scale=900:-1:flags=lanczos" -c:v gif -loop 0 assets/demo.gif
```

---

## 📊 Why each choice was made

| Choice | Reason |
|---|---|
| Offline demo target | Removes every reason a first visitor can bounce: no network, no key, no third-party rate limit, no legal risk |
| stdlib-only core | A Space that installs 400MB of wheels loses people during cold start. Zero-dep core = fast boot = more stars |
| 12 languages | Each one is a community that finds the project on its own. Hindi and Arabic are almost certainly under-served |
| Real CVSS numbers | "CVSS-like" is a smell. Publishing the cross-validation against a reference implementation is the credibility play |
| Honest limitations | The people who reply to your issues are security people. They can smell marketing instantly |
| SARIF output | Code-scanning integrations are how a scanner gets adopted, and adoption is what creates downloads |
| SARIF/JSON/HTML/MD | Every format is a different kind of user: CI, a manager, a designer, an issue tracker |
| No GPU in the demo | Multimodal-in-a-trenchcoat sounds better than a 90-second cold start |
| Community section | Payload contributions grow the catalogue without you, and each contributor brings their audience |

---

## 🧮 Realistic expectations

| Milestone | Time | What it takes |
|---|---|---|
| 10 stars | 1–2 days | One good post, the demo GIF |
| 100 stars | 2–3 weeks | Consistency + one newsletter pickup |
| 500 stars | 6–10 weeks | A viral post or a HN front page, plus the changelog cadence |
| 1K stars | 3–6 months | Usually one big break, then compounding from the community |

Downloads follow stars for a scanner, because the install is `pip install` and
there is no inference to be fast about. Keeping the changelog moving is what
turns a spike into a baseline.

---

## ⚠️ One thing that will hurt you

Do not invite people to "test the tool on a site." Get a bug bounty scope, an
explicit written authorization, or use the bundled demo. The second you ship
something that makes it easy to point a scanner at someone else's production
box, you'll get one very bad story and one very quiet project.

The disclaimer in the Space isn't decoration. Keep it.