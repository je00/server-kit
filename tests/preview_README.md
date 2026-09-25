# Local visual review

Use a Python environment with the dependencies in `web/requirements.txt`:

```sh
python tests/run_web_preview.py
```

Open <http://127.0.0.1:8765/__preview__/>.
Sign in with **preview / Preview-only-2026!**. A read-only account, **viewer**,
uses the same demo password. These are local demo credentials only.

The index lists every main page, all service details, eight task states and
thirteen confirmation variants. Fixtures include long names, port ranges,
IPv6, disabled nodes, errors, empty lists and rollback countdowns.

```sh
python tests/run_web_preview.py --check
python tests/run_web_preview.py --port 8766 --scenario empty
python tests/run_web_preview.py --port 8767 --scenario error
python tests/run_web_preview.py --port 8768 --scenario pending
python -m unittest discover -s tests -p test_web_preview.py
```

Optional repeatable browser audit (install Playwright and Chromium in a local
development environment, not on the VPS):

```sh
node tests/run_web_visual_audit.cjs http://127.0.0.1:8765/
node tests/run_mobile_render_ui.cjs http://127.0.0.1:8765/
node tests/run_login_ui.cjs http://127.0.0.1:8765/
```

It signs in with the demo account, captures all 40 routes at 320, 390, 768 and
1440 pixels, checks page overflow/headings, and writes PNGs plus `report.json`
to a new temporary directory. All non-preview-origin requests are blocked.
Inspect screenshots too: automated checks cannot judge visual hierarchy.

The mobile rendering regression also needs WebKit. It checks each theme button
against its own container (not just page overflow), distinguishes the current
page from an expanded More menu, and exercises short viewports, menu scrolling,
theme changes, and the login theme picker. Fixtures and screenshots stay local.

The login regression uses Chromium and WebKit: normal and deep-link login,
duplicate submits, stale tabs after CSRF rotation, and safe GET-only recovery.
Anonymous, cross-origin and non-login invalid forms must still return 403.
It records synthetic screenshots and cookie-change booleans, never cookie values.

The default rich scenario renders 40 review routes. Use the index to reset or
switch scenarios; this resets every tab attached to that instance, so use a
separate port for simultaneous reviews. Static files and templates reflect
edits on reload. Restart the preview to pick up Python code changes.

Safety boundaries:

- Binds only `127.0.0.1`; no configurable external listener.
- Creates a new private temporary SQLite database, upload area and fake-agent
  socket; inherited production state/socket/secret paths are overridden.
- Uses synthetic `example` domains, documentation addresses and in-memory
  task results. Never imports a host command runner or contacts a VPS.
- Unknown agent actions fail closed. Confirming a form only changes fixtures
  in memory; account and upload actions affect temporary preview state only.
- Fixture routes are selected only by this launcher, not production settings.
- Temporary state is removed on normal exit. Do not enter real credentials
  or upload real sensitive files in a demo environment.
