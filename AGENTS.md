# AGENTS.md

## What is this

Electron 22 LAN messaging + file transfer app (P2P, no server). Chinese-first project with bilingual docs.

## Hard constraints

- **Electron locked to 22.3.27** — never upgrade, no `^`/`~` in package.json
- **Main process: Node 16.17** — no `fetch`, no `structuredClone`, use `net`/`dgram`/`http`
- **Renderer: Chrome 108** — no CSS nesting, Popover, `text-wrap: balance`, subgrid
- Build targets fixed in `electron.vite.config.ts`
- **better-sqlite3** is the only native module; rebuild with `npm run rebuild:electron`
- All deps pinned (`npm i -E`), never run `npm update` or `npm audit fix --force`

## Commands

```bash
npm run dev          # Start dev (hot reload)
npm run dev:2        # Two local clients for integration testing
npm run dev:3        # Three local clients

# Verification (run before any commit)
npm test             # Protocol codec + discovery loopback + pure functions
npm run test:db      # Migrations/repo/FTS on real Electron ABI
npm run typecheck    # node16 + chrome108 type baselines
npm run build        # Three-target build (main/preload/renderer)
npm run smoke        # Build + 1.5s clean exit (exit code 0)

# Single test file
npx vitest run path/to/file.test.ts
```

## Architecture

Three processes, one-way dependency:

- `renderer/` — Vue 3 + Pinia, never imports electron/node directly, uses `window.pantry`
- `main/` — Node 16: `net/` (network), `store/` (SQLite), `services/` (orchestration), `windows/`
- `shared/` — Types + constants only, zero runtime deps

Layer rules:
- `net/` and `store/` have zero Electron dependencies (vitest runs them directly)
- Business logic belongs in `services/`, not in IPC handlers (`main/index.ts`)
- `shared/ipc.ts` is the single source of truth for the `window.pantry` API contract

## Key gotchas

- **Chinese-first**: docs, comments, commit messages, UI text all use simplified Chinese
- **Bilingual docs**: every Chinese `.md` has an English counterpart; `npm run check:docs` verifies sync
- **Network tests bind to 127.0.0.1** — never send packets to real LAN
- **DB migrations append-only** — never modify published migrations
- **Native module rebuild**: `postinstall` handles this; if Electron fails to start, check `node_modules/better-sqlite3`
- **OCR assets** are copied by `scripts/prepare-ocr-assets.mjs` during `dev` and `build`
- **macOS unsigned**: first launch needs `xattr -dr com.apple.quarantine`
- **Commit prefixes**: `feat` / `fix` / `docs` / `refactor` / `test` / `chore` + Chinese description

## Testing

- 90+ test files across `src/`, mostly `*.test.ts`
- `net/`, `store/`, `util/` tests run standalone via vitest (no Electron needed)
- `test:db` uses `esbuild` to bundle then runs in Electron's Node for real ABI compat
- CI runs five-step verification on every platform (Win x64/ia32, Linux x64/arm64, macOS arm64)

## Common tasks

| Task | Where to change |
|---|---|
| New message type | `shared/protocol.ts` → `net/codec.ts` → `services/` → renderer |
| New UI component | `renderer/src/components/`, use `styles/tokens.css` variables |
| New setting | `shared/ipc.ts` → `preload` → `main/index.ts` → `store/app-state.ts` → `SettingsApp.vue` |
| New DB table/field | `store/migrations.ts` (append only) → `*-repo.ts` → `npm run test:db` |
| New window | `main/windows/` + `renderer/src/` with hash route in `main.ts` |

## References

- [CONTRIBUTING.md](CONTRIBUTING.md) — environment setup, build, dist commands, hard rules
- [DEVELOPMENT.md](DEVELOPMENT.md) — architecture deep-dive, module responsibilities, data flow
- [docs/handoff.md](docs/handoff.md) — current state, workflow, code map, next steps
- [docs/protocol.md](docs/protocol.md) — wire protocol, message types, constants (Chinese is source of truth)
- [docs/tech-design.md](docs/tech-design.md) — tech decisions, IPC contracts, database schema
