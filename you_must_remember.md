# Things to remember

## LLM connection details for testing (provided 2026-09-30)
- **Endpoint:** https://api.xkiro.com/v1 (OpenAI-compatible)
- **API key:** sk-xt-cc3635e463039f2243cb979bf74c8ff1aa41c98b6f52077d
- **Model:** z-ai/glm-5.3-flash
- Configure these in `.env` as `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL`.
  The key lives only in `.env` (gitignored) — never in the DB, UI, or repo.

## Default platform admin account
- Current demo database (`instance/asm.db`, rebuilt 2026-10-01): username `admin`,
  password `kOR39iYDVlny_gP1` (a fresh `--init-db`/`--demo` generates a new random
  password printed once to the console).

## Demo users (synthetic demo dataset)
- `demo_analyst` / `demo_author` / `demo_admin` — password `DemoPass123!` (demo only)

## Database location (important!)
- The SQLite DB is at `/home/kali/asm_data/asm.db` (LOCAL disk), set via `DATABASE_URL`
  in `.env`. SQLite locking is broken on the VMware hgfs share — never move the DB back
  to `ASM/instance/`.

## ZAP integration (installed 2026-10-16)
- Package: `zaproxy` 2.17.0-0kali1
- Binary: `/usr/share/zaproxy/zap.sh` (pinned as `ZAP_BINARY` in `.env`)
- Tool Status should show ZAP installed; select `vulnerability_scan` → `zap` in New Scan.
- ZAP JSON alerts now normalize into the shared findings/risk/STRIDE pipeline.

## Key commands
- `python run.py --demo` — init DB + load synthetic demo data
- `python run.py --test-llm` — verify the LLM connection
- `python run.py` — start the web app on http://0.0.0.0:5000
