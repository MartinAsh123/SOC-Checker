# SOC-Checker

An interactive Bash lab tool for generating network-scan and authentication-test activity so a SOC can observe alerts and investigate the resulting telemetry.

## Current status

The repository contains [sochecker.sh](sochecker.sh). It passes a Bash syntax check. No network scans, NSE scripts, or authentication attempts were executed during this documentation review.

The script generates activity; it does **not** connect to a SIEM, verify that an alert fired, measure analyst response, or produce a complete detection-validation report.

## Existing workflow

The script accepts an IP address or CIDR range and prompts for a scanning method:

| Menu | Current behavior |
| --- | --- |
| Scan method 1 | Expands the target with Nmap list scanning, then launches background full-port scans with host discovery skipped. |
| Scan method 2 | Uses an initial Nmap NULL scan and parses its output, then launches background full-port scans against the resulting entries. |
| Follow-up 1 | Lists candidate enumeration NSE scripts using the local `locate` database and runs the selected script. |
| Follow-up 2 | Invokes Hydra with a generated username list and a hard-coded local password-list path. |

Both full-port scan paths use `-T5`. The workflow can generate substantial traffic and authentication failures. Use it only against explicitly authorized lab targets and agreed test scopes.

## Requirements

- Linux with Bash.
- Nmap.
- `locate` with a populated file database for the enumeration menu.
- Hydra and the password-list file referenced in the source for the authentication-test menu.
- `sudo` privileges for the initial NULL scan in method 2.
- Standard utilities including `awk`, `grep`, `ps`, `sort`, `tee`, and filesystem commands.
- A writable working directory.

The script does not currently validate these dependencies.

## Invocation

```text
bash sochecker.sh <IP-or-CIDR>
```

Select the scan method and follow-up action interactively. There is no built-in `--help`, scan-only mode, dry run, or automatic SOC integration.

## Output

The script derives an output directory from the target by removing the CIDR suffix.

- Per-host scan text is initially written below that directory.
- Files identified as containing open ports are moved into an `IPS/` subdirectory.
- `atk.log` records the start of enumeration or authentication-test actions.
- A username list is created if the authentication-test menu is selected.
- Method 1 writes `Ip.lst` into the working directory; method 2 writes `IP.lst` inside the target directory.

Some intermediate scan files are deleted. The follow-up tools' full output is not consistently saved, so these files are not a complete audit trail.

## Known limitations

- **Arguments and selections are not validated.** Missing targets, unexpected text, and unquoted paths can lead to incorrect command or filesystem behavior.
- **Method 1 does not reliably wait for every scan.** It uses process-list matching and selected PIDs rather than tracking all child jobs.
- **Concurrency is inconsistent.** Method 1 attempts a process-count threshold; method 2 launches scans without a limit.
- **Host parsing is fragile.** Reverse-DNS names can appear in list-scan output, and the filter for `.0` can exclude more addresses than intended.
- **The second discovery method is mislabeled.** `-sN` is a NULL port scan; it is not a dedicated discovery-only workflow.
- **Open-port detection parses human-readable text.** Searching for `open` does not reliably distinguish exact port states.
- **NSE selection depends on filenames and the local locate database.** The selected script is not checked against a defined allowlist.
- **Authentication-test settings are hard-coded.** The script lacks an explicit account-lockout budget or a second confirmation before that action.
- Reusing output directories can mix old and new results; cleanup can discard useful evidence.

## Potential improvements

- Add strict target/input validation, dependency checks, and `--help`.
- Create a separate output directory for each run and retain original results.
- Use structured Nmap output, bounded concurrency, and reliable job tracking.
- Add scan-only and dry-run modes with explicit scope and intensity settings.
- Require a separate opt-in for authentication tests, with agreed attempt limits.
- Record timestamps, selected actions, tool exit codes, and full output for comparison with SOC alerts.

These improvements are proposed, not implemented.
