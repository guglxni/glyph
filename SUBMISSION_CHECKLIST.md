# GLYPH — Capstone Submission Checklist

Fellowship requirements (hard) and recommended items, with live status.

## Hard requirements

| # | Requirement | Status | Evidence / Notes |
|---|-------------|--------|------------------|
| 1 | Public GitHub repository | ✅ DONE | Public at https://github.com/guglxni/glyph |
| 2 | Clear setup instructions + proper README | ✅ DONE | README rewritten: prerequisites w/ versions, build/test, anchor build, worker dev mode, demo. |
| 3 | All required code pushed to GitHub | ✅ DONE | 612 files pushed to `main`; no secrets/bloat (verified against remote tree). |
| 4 | Push before 11:00 PM cutoff (no commits after) | ⏳ ACTION | Initial push DONE. Do the final commit (after recording video link) well before 11:00 PM. |
| 5 | (Submission) repo link submitted to fellowship | ⏳ ACTION | Submit https://github.com/guglxni/glyph after final push. |

## Recommended (Top-20)

| # | Item | Status | Evidence / Notes |
|---|------|--------|------------------|
| 6 | Live demo link | ✅ DONE | https://web-lovat-seven-23.vercel.app (HTTP 200, public). In-browser commitment parity to Rust canonicalization. |
| 7 | Demo video (Loom) | ⏳ ACTION | Script in README/notes; record, then paste link into README `<DEMO_VIDEO_URL>` and push. |
| 8 | Live program (devnet) | ✅ DONE | `G5RnXgNZYiS4NJey6JzyxTLvPPPUMqUDL7wg6nqaMD3g` deployed + initialized + VK seeded. |

## Quality bar (self-imposed)

| # | Item | Status | Evidence |
|---|------|--------|----------|
| 9 | Workspace builds clean | ✅ DONE | `cargo build --workspace` 0 warnings. |
| 10 | Tests pass | ✅ DONE | 114 tests pass (tee-worker + common + circuit host). |
| 11 | No secrets committed | ✅ DONE | Verified remote tree: no keypair/.pem/session/target/node_modules. |
| 12 | Multi-protocol demo | ✅ DONE | One policy, 3 programs, shared commitment `d086deb3…0053cb`; 4th denied. |

## Remaining actions before submitting
1. (Optional but recommended) Record the Loom demo using the script in the project notes.
2. Paste the video link into `README.md` (replace `<DEMO_VIDEO_URL>`).
3. `git add -A && git commit && git push` — **before 11:00 PM**.
4. Submit https://github.com/guglxni/glyph to the fellowship form.
