# Session Summary

## Current request: ZAP appears stuck at "Active scanning"
- User ran ZAP quick scan against authorized Metasploitable2 target `http://192.168.245.131/mutillidae/`; the UI showed "Active scanning" with no visible progress; another scanner completed.
- Investigation: the target stayed responsive, the Java process consumed CPU/memory, the scanner later printed `Attack complete`, wrote `report.json`, and the job completed with findings after about 27 minutes.
- No server errors were logged and the process was not hung; the main issue was slow active scanning with poor progress visibility.
- Root cause: ZAP progress uses carriage-return updates, while the worker originally only moved progress from 5% to 100% at completion.
- Fix applied: carriage-return progress is split into live updates, phase/progress values are persisted, and the job page updates output, phase, progress, and status. Regression tests pass.

## Previous request: real-time scan output on `/scans/<job id>`
- Live Tool Output persists while jobs run with throttled database writes.
- The job page polls every second and reloads once at completion.
- Browser verification showed output increasing during a crawl and no browser/server errors.

## Earlier completed work
- Derived scan data was removed from `/home/kali/asm_data/asm.db`; users, organizations, policies, and schedules were preserved. Backups were created.
- Amass was removed from runtime scanner, policy, route, scheduler, LLM, demo, and template references; passive reconnaissance maps to subfinder.
- Installed scanner dependencies and corrected several adapter command/output mismatches; the full suite passed after those changes.
- Browser sessions and dashboards were closed after QA runs.
- Authorized targets: `http://192.168.245.131/mutillidae/` and `http://192.168.245.131/dvwa/login.php` only.
- The findings page is `/vulnerabilities/`, not `/vulns`.

## Persistent collaboration preference
- For each task, keep a concise project-local `SESSION_SUMMARY.md` with the user's request, what was done, and what remains. CodeGraph maps code; it is not conversation history.
