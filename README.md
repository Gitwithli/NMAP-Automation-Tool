# nmapflow

Interactive Nmap automation and reporting for Kali Linux and other Linux systems.
**For systems you own or are explicitly authorized to assess.** Python 3.10+, standard library only.
It offers 156 scan profiles, 55 NSE entries (categories, scripts, bundles), HTML and XML reports, and it never starts a scan
without two explicit confirmations.

## Install and run on Kali

```bash
sudo apt update && sudo apt install -y nmap iproute2     # both are usually preinstalled on Kali
python3 --version                                         # must be 3.10 or newer
nmap --version
```


```bash
git clone https://github.com/Kali-Nima/NMAP-Automation-Tool
cd nmapflow
sudo python3 nmapflow.py          # root enables SYN/ACK/UDP scans, OS detection, traceroute
python3 nmapflow.py               # works without root; root-only scans are offered but can be skipped
python3 -m nmapflow               # same program
```

Reports are written to `reports/YYYY-MM-DD_HH-MM-SS/` (owned by you even when started with sudo).

Dependencies and why: **Python 3.10+** (runtime), **Nmap** (the scanner), **iproute2** (`ip -j addr`, to list local subnets; the tool
falls back to a guess if it is missing). Nothing else: no third-party Python packages.

Helper commands (none of them starts a scan):

```bash
python3 nmapflow.py --list-profiles            # every profile with its exact Nmap arguments
python3 nmapflow.py --show-profile 5           # one profile in detail (number or ID)
python3 nmapflow.py --list-nse                 # NSE catalog
python3 nmapflow.py --export-catalog docs/PROFILES.md
python3 nmapflow.py --config FILE --reports-dir DIR
python3 nmapflow.py --version
```

## Typical session

```
Select: 2                                   # multiple hosts
Targets: 192.168.10.2 192.168.10.5 @hosts.txt
Targets to EXCLUDE: 192.168.10.5
Type AUTHORIZED to confirm: AUTHORIZED      # scope confirmation (required)
profiles> 4,7,8                             # numbers, ranges (4-8), c3 (a category), /ssh (search), custom
profiles> done
Add NSE scripts? y   ->   nse> 47,48        # bundles, scripts or categories; independent of profiles
Timing [T3]: 3
Type RUN to start                           # plan review: exact commands, warnings (required)
```

Ctrl+C during a scan asks: continue, skip the running scan(s), or stop everything. Partial results are kept.
`python3 nmapflow.py` has no unattended mode on purpose: there is no option that starts a scan without the two confirmations.

## Documentation

| File | Contents |
|---|---|
| `docs/PROFILES.md` | all 156 profiles with exact Nmap arguments, risk, duration, root requirement and notes (generated) |
| `docs/TESTING.md` | test strategy, how to run, inventory, results, bugs found and fixed, local-lab workflow, examples |
| `docs/DEBUGGING.md` | where to look, common problems and fixes, reproducing a scan by hand |

## Modules

| Module | Job |
|---|---|
| `cli.py` | menus, prompts, status output, entry point |
| `config.py` | settings (`config.json`), validation |
| `models.py` | dataclasses: targets, profiles, tasks, parsed results |
| `targets.py` | parse/validate IPs, hostnames, CIDR, ranges, files; dedupe; exclusions; scope warnings |
| `netdetect.py` | local interfaces/subnets (`ip -j addr`, fallback) |
| `profiles.py` | profile catalog generated from reusable parts; custom profiles |
| `customargs.py` | allow-list validation of custom Nmap arguments and port specs |
| `nse.py` | NSE catalog, safety guard expression, `script.db` availability checks |
| `planner.py` | targets x profiles x NSE -> tasks; chunking; duplicate detection; the single place that builds Nmap commands |
| `privileges.py` | which options need root |
| `runner.py` | launches Nmap (`Popen`, argument list, no shell), concurrency, per-host locking, timeouts, cancellation |
| `parser.py` | Nmap XML -> objects (ElementTree; truncated-XML recovery on an in-memory copy) |
| `session.py` | session folders, `session.json`, confirmation gate, listing old sessions |
| `aggregate.py` | merges task results per host; finds script-reported issues |
| `report_html.py` | self-contained offline HTML report |
| `report_xml.py` | `session.xml` (custom format referencing the untouched Nmap XML) |
| `utils.py` | time, atomic file writes, hashing, logging, terminal colour |

## Output per session

```
reports/2026-11-04_14-30-00/
  report.html   session.xml   session.json   session.log
  tasks/003_<name>/  scan.xml  scan.nmap  command.txt  stdout.log  stderr.log  meta.json
```

Original `scan.xml` / `scan.nmap` are written once by Nmap, made read-only, fingerprinted (SHA-256) and never edited or overwritten
(a pre-existing file makes the task fail instead). `session.xml` is **not** native Nmap XML; it records scope, authorization and one
`<task>` per scan with the path and hash of its original XML. Removed, skipped, failed, timed-out and cancelled tasks all stay in
`session.json`, `session.xml` and `report.html`.

## Settings (`config.json`, created from the Settings menu)

`timing` (3), `concurrency` (1, max 8), `output_dir` (`reports`), `timeout_minutes` (240, 0 = none), `default_profiles`, `default_nse`,
`host_discovery` (true; false adds `-Pn`), `resolve_dns` (false; adds `-n`), `hosts_per_task` (0 = automatic), `prefer_ipv6`,
`nse_category_udp_top_ports` (0), `nmap_path`.

With concurrency above 1 the targets are split so different hosts scan in parallel; two scans never touch the same host at once.

## Safety behaviour

- No scan starts without typing `AUTHORIZED` (scope) and `RUN` (plan). The runner re-checks both and refuses otherwise.
- Public addresses and /16-or-larger ranges need an extra explicit confirmation.
- Nmap is always started with an argument list; there is no `shell=True`. Targets starting with `-` are rejected.
- Only safe NSE scripts are offered. Categories are wrapped in `... and not (intrusive or dos or exploit or brute or fuzzer or external or broadcast)`.
  `ssl-enum-ciphers` (Nmap labels it intrusive) and the external `vulners` lookup are explicit opt-ins.
- A scan result never proves a host is secure or that every vulnerability was found. Nmap is not a substitute for a full
  vulnerability assessment or a manual penetration test.

## Testing

```bash
python3 -m unittest discover                     # 428 tests; uses a fake nmap, scans nothing
python3 -W error::ResourceWarning -m unittest discover
NMAPFLOW_LIVE_TESTS=1 python3 -m unittest tests.test_live_localhost -v     # optional, real Nmap, 127.0.0.1 only
```

See `docs/TESTING.md` for results, coverage and the local-lab workflow.

## Known limitations

* Tested on Ubuntu 24.04 with Nmap 7.94 (Debian family, like Kali). It has not been run on a physical Kali installation; Kali's newer Nmap should behave the same,
  and the tool re-checks the NSE script catalog against whatever Nmap is installed.
* IPv6 targets are covered by unit tests (the `-6` flag, family splitting, parsing of IPv6 XML) but were not live-scanned: the build machine had no IPv6 stack.
* Live (real Nmap) tests cover connect and SYN scans, NSE, timeouts and option parsing on loopback. UDP, ACK/Window/Null/FIN/Xmas and OS detection profiles are
  checked for valid options against real Nmap and executed against the fake Nmap, but not live-scanned in the automated suite.
* The HTML report's layout (CSS, dark mode, print) was not viewed in a real browser; its JavaScript behaviour (sort, filter, expand/collapse, print handler) is tested in jsdom.
* An interrupted Nmap may leave a truncated XML file: hosts that were fully written are kept, a half-written host is lost from the XML (its text file and logs remain).
* Progress percentages come from Nmap's English `--stats-every` lines and only appear for scans long enough to print them. Results never depend on them.
* The per-host lock works inside one nmapflow process; two separate instances can scan the same host at the same time.
* Single hosts are not scanned in parallel (concurrency splits different hosts only).
* Linux is the supported platform. The code avoids Linux-only calls where practical, but Windows is untested.
* The typed `AUTHORIZED` confirmation records your attestation; the tool cannot verify that you really are authorized.
* Hostnames are resolved once at planning time with the system resolver; slow DNS can delay the scope screen by a few seconds.

## Feature checklist

| Requirement | Implemented in | Verified by |
|---|---|---|
| Runs on Kali/Linux, Python 3, interactive terminal UI | `cli.py` | `test_cli` |
| Single host, multiple hosts, local network (subnet detection, manual CIDR), previous sessions, exit | `cli.py`, `netdetect.py` | `test_cli.MainMenu`, `SingleHostFlow`, `MultipleHosts`, `NetworkMode`, `PreviousSessions` |
| Target validation, de-duplication, originals preserved, exclusions, file import, scope confirmation | `targets.py`, `cli.py` | `test_targets`, `test_cli.NothingRunsWithoutConfirmation` |
| 156 profiles incl. the required eight (+2 literal-flag companions), risk/duration/notes, documented arguments | `profiles.py`, `docs/PROFILES.md` | `test_profiles`, `test_static_and_docs` |
| Select one, several (`4,7,8`), a whole category, or a custom profile | `cli.py`, `profiles.py`, `customargs.py` | `test_cli.ProfileSelection`, `test_customargs` |
| Timing T1-T5 (default T3) with explanation | `cli.py` | `test_cli.TimingAndOptions` |
| Review the complete plan before execution | `cli.py` | `test_cli.PlanReviewBehaviour` |
| Separate NSE menu, safe by default, opt-ins, validation, no brute/dos/exploit/fuzzer/intrusive | `nse.py` | `test_nse`, `test_planner.NseIndependentFromProfiles` |
| Multiple scans per target, never silently omit a scan (all statuses recorded) | `planner.py`, `runner.py`, `session.py` | `test_runner`, `test_reports`, `test_cli.PlanReviewBehaviour` |
| Current scan, command and progress shown | `runner.py` | `test_runner.SuccessfulRun.test_progress_and_open_port_counting` |
| Safe subprocess use (argument list, no shell, option-injection refusal) | `planner.build_command`, `runner.py` | `test_runner.SafeSubprocessUse`, `test_planner.CommandBuilding`, `test_static_and_docs` |
| Root/privilege checks and explanation | `privileges.py`, `cli.py` | `test_cli.RootHandling`, `test_config_privileges_net` |
| Sequential or limited concurrency, configurable limit, per-host locking | `runner.py`, `planner.py` | `test_runner.ConcurrencyAndLocking`, `test_planner` |
| Timeouts, cancellation (Ctrl+C), partial results kept, child processes terminated | `runner.py` | `test_runner.Timeouts`, `Cancellation` |
| Duplicate scans avoided (flagged, user decides) | `planner.py`, `cli.py` | `test_planner.Duplicates`, `test_cli.PlanReviewBehaviour` |
| Per-scan XML, text output, command, targets, timestamps, exit code, error logs | `runner.py`, `session.py` | `test_runner.SuccessfulRun` |
| Original output preserved: read-only, hashed, never overwritten | `runner.py`, `aggregate.py` | `test_session_integrity`, `test_runner.FailureModes` |
| XML parsing with a real parser, tolerant of incomplete data | `parser.py` | `test_parser` |
| HTML report (summary, scope, runs, discovery, ports, versions, OS, scripts, findings, errors, recommendations/limitations; search, sort, expand, TOC, responsive, print, dark/light, offline) | `report_html.py` | `test_reports`, `test_report_js` |
| Severity wording only where scripts state it; no invented scores | `aggregate.py`, `report_html.py` | `test_reports.ClassifyFindings` |
| Consolidated XML that is not mislabelled as Nmap XML | `report_xml.py` | `test_session_integrity.SessionXml` |
| Configuration (timing, concurrency, output dir, timeout, default profiles/NSE, discovery, DNS) | `config.py`, `cli.py` | `test_config_privileges_net`, `test_cli.DefaultsAndSettings` |
| No scan without explicit target confirmation; no headless mode | `session.py`, `cli.py`, `runner.py` | `test_runner.ConfirmationGate`, `test_cli.NothingRunsWithoutConfirmation` |
| Dependencies explained; Kali install commands | this file | `test_static_and_docs.Documentation` |
