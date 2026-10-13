# SOC-Checker

A small command-line tool for generating scoped network activity and keeping the results for comparison with SOC alerts. It does not connect to a SIEM or automatically determine whether a detection succeeded.

## Current implementation

The Bash entry point, [sochecker.sh](sochecker.sh), starts a Python standard-library runner, [soc_checker.py](soc_checker.py). The runner validates targets, manages child processes, parses Nmap XML, and preserves a separate directory for every run.

- IPv4 addresses and CIDRs only, with a maximum scope of 256 addresses.
- Discovery followed by full TCP scans by default; explicit all-host and NULL-scan modes are available.
- Four concurrent scan processes by default, configurable from 1 to 16.
- Nmap timing defaults to `-T3` rather than the original `-T5`.
- Every scan finishes or fails before a follow-up can begin. Failed scans cause a nonzero exit and skip follow-up actions.
- Exact `open` port states are read from XML; `open|filtered` is not reported as definitely open.
- NSE and authentication tests are separate opt-in actions. The default stops after scanning.

## Requirements

- Linux, Bash, and Python 3.9 or newer.
- Nmap for live scanning.
- Root for `--mode null`; the tool does not invoke sudo automatically.
- Hydra only when choosing an authentication test.

There are no third-party Python dependencies. `--help` and `--dry-run` do not require Nmap or Hydra. Use explicitly authorized test scopes; scan and authentication traffic can affect monitored systems.

## Usage

Inspect a plan without starting tools, creating output, or making connections:

```bash
bash sochecker.sh 192.0.2.0/24 --dry-run
```

The example address space is reserved for documentation; replace it with your authorized lab scope for actual runs.

```text
bash sochecker.sh <IPv4-or-CIDR> --scan-only
bash sochecker.sh <IPv4-or-CIDR> --mode all --jobs 2 --output-dir ./soc-runs
bash sochecker.sh <IPv4-or-CIDR> --follow-up menu
bash sochecker.sh --help
```

| Option | Behavior |
| --- | --- |
| `--mode discover` | `-sn` discovery, then full TCP connect scans of discovered hosts (default). |
| `--mode all` | Full TCP connect scans of all usable addresses in the scope, skipping discovery. `/31` and `/32` follow Python's host-address handling. |
| `--mode null` | Explicit NULL port scan, then full TCP connect scans of the hosts reported up; requires root. |
| `--jobs 1..16` | Maximum concurrent full-port scan processes (default 4). |
| `--timing 0..5` | Nmap timing template (default 3). |
| `--timeout SECONDS` | Per-tool timeout (default 600 seconds). A timeout is recorded as failure. |
| `--output-dir PATH` | Parent directory for a newly created run directory. |
| `--scan-only` | Explicitly disable follow-up actions; this is also the default. |
| `--follow-up menu` | Offer finish, NSE, or authentication testing after successful scans. |
| `--follow-up nse` | Select an allowed NSE script and a successfully scanned host. |
| `--follow-up auth` | Select a controlled authentication test, with a separate typed confirmation. |
| `--host IPv4` | Follow-up target; must be in scope and appear in this run's successful scan output. |
| `--dry-run` | Print the scan plan without executing it. |

Full scans use `-n -sT -Pn -p-`. Discovery can miss filtered hosts; use the explicit `all` mode when that behavior is appropriate for the agreed test.

### Follow-up constraints

Follow-up actions require an interactive terminal. The NSE allowlist is `http-title`, `ssh-hostkey`, `ssl-cert`, and `smb-os-discovery`; choose with `--nse-script` or the prompt. A failed scan prevents all follow-up actions.

Authentication testing requires user-supplied `--user-list` and `--password-list` files, approved test accounts, a supported `--service` (`ssh`, `ftp`, `rdp`, or `smb`), and typing `AUTH TEST` at the confirmation prompt. It uses one Hydra worker and stops after a successful pair. There is no bundled default-account list or hard-coded password dictionary.

The candidate budget is at most **3 pairs per account** and **10 pairs in total**; duplicate usernames count toward the same account's budget. The validated lists are copied into private temporary files and removed afterward. These limits count candidate pairs, not guaranteed wire-level requests: protocol retries and existing server lockout counters can still cause lockouts. They are not a lockout-prevention guarantee.

## Output and exit status

Each run creates a private directory below `soc-runs/` (or the selected parent). Directories use mode `0700` and newly created files use restrictive permissions.

- `summary.json`: scope, settings, timestamps, successful host results, errors, and overall status.
- `events.jsonl`: tool argument lists, start/end times, exit codes, and timeout/error details.
- `nmap-version.stdout`: the Nmap version output.
- `discovery.xml` and per-host `.xml` files: structured scan results.
- Per-tool `.stdout` and `.stderr` files: original output, including failures.
- Optional `nse.xml` and follow-up logs.

Authentication output can include credentials reported by Hydra; protect the run directory accordingly. Original results are retained, including unsuccessful scans. Nothing is deleted from previous runs.

Exit codes: `0` means the selected workflow completed, `1` means a runtime/tool failure, `2` means invalid arguments or unmet preconditions, and `130` means interruption. Completion is not evidence that a SOC alert fired. Ctrl+C or SIGTERM stops the child processes started by this run and preserves the summary.

## Tests and validation

```bash
python3 -m unittest discover -s tests -v
bash -n sochecker.sh
```

Tests use a fake Nmap executable and synthetic XML. They cover target validation, follow-up scope, exact port states, authentication budgets/confirmation, bounded concurrency and waiting, unique output paths, timeouts, and error reporting. No live network scan or authentication attempt is part of the test suite. Real Nmap/Hydra compatibility and SOC detection behavior still require validation in your lab.
