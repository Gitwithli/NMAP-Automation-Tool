# nmapflow: testing guide

Everything here describes the suite as shipped. `python3 -m unittest discover` runs it.

## 1. Strategy

* **No automated test scans anything.** Tests run a **fake `nmap`**: a real executable script (`tests/helpers.py`) that parses the
  arguments the tool gave it, writes canned XML/text output files, and can be told to behave badly (fail, hang, ignore signals,
  write broken XML, print progress, run slowly). The runner therefore exercises real processes, pipes, signals, timeouts and
  process-group handling, but nothing ever touches a network. Each fake invocation is logged to a file so tests can check the
  exact command line, start/end times and how many processes ran at once.
* **Real Nmap is used only in two places:** the XML fixture `tests/fixtures/real_localhost.xml` (captured from a real Nmap 7.94 scanning
  this machine's own loopback) and the optional live tests below, which only ever target `127.0.0.1`.
* Standard library only (`unittest`, `unittest.mock`). Optional extras for developers are listed in section 6.

## 2. Running the tests

```bash
cd nmapflow
python3 -m unittest discover                      # everything (about 80 s; fake nmap only)
python3 -m unittest discover -v                   # one line per test
python3 -m unittest tests.test_planner            # one file
python3 -m unittest tests.test_runner.Cancellation.test_ctrl_c_stop_keeps_partial_results_and_marks_everything
python3 -W error::ResourceWarning -m unittest discover    # also fail on leaked file descriptors (recommended)
python3 -m unittest discover -f                   # stop at the first failure
```

Run the suite once as a normal user as well as root: a few tests (read-only originals, non-executable Nmap) only run when the
process is NOT root, because root bypasses file permissions.

```bash
sudo python3 -m unittest discover                 # root run
python3 -m unittest discover                      # normal-user run (permission tests included)
```

Optional live tests (real Nmap, loopback only, a few seconds to a minute):

```bash
sudo apt install -y nmap
NMAPFLOW_LIVE_TESTS=1 python3 -m unittest tests.test_live_localhost -v        # add sudo to include the SYN-scan test
```

Optional browser-behaviour test (sorting, filtering, expand/collapse and print handler of `report.html`, run in jsdom):

```bash
sudo apt install -y nodejs npm
mkdir -p /tmp/jsd && (cd /tmp/jsd && npm install jsdom)
NMAPFLOW_JSDOM=/tmp/jsd/node_modules python3 -m unittest tests.test_report_js -v
```

## 3. What each file covers

| File | Tests | Covers |
|---|---|---|
| `test_targets.py` | 29 | valid/invalid IPv4, IPv6, hostnames, CIDR, ranges; shell metacharacters and option-like input; de-duplication; originals preserved; exclusions; IPv4/IPv6 split; hostname resolution (mocked); public and large-range detection; target files (comments, missing, too large, bad UTF-8) |
| `test_customargs.py` | 6 | port-spec validation; allow-list of custom Nmap options; 38 rejected inputs with reasons (output files, targets, timing, scripts, spoofing, shell syntax) |
| `test_config_privileges_net.py` | 20 | settings defaults, validation, round trip, corrupt files; which options need root; interface/subnet detection from `ip -j` (mocked) and fallbacks |
| `test_profiles.py` | 29 | **all 156 profiles**: unique IDs, numbering, categories, required fields, risk/duration labels, root requirements, valid Nmap options, banned options absent, guarded script expressions; the ten required slots exactly; custom profiles; rendering/export; every profile through the planner and through the fake Nmap |
| `test_nse.py` | 29 | catalog numbering (1-55), guard expression, opt-in scripts, `script.db` parsing and availability, name validation, selection to task groups, TCP/UDP grouping, unavailable/unconfirmed scripts reported |
| `test_planner.py` | 39 | task construction, flags (`-n`, `-Pn`, `-6`), exclusions, chunking (every address assigned exactly once), per-host splitting limits, duplicate detection, opt-in handling, script filtering, **NSE independent of profiles**, command layout and option-injection refusal, same-host lock rules |
| `test_runner.py` | 46 | successful runs and preserved outputs; read-only originals; no shell / list arguments; confirmation gate; skipped tasks; failures (exit code, no XML, broken XML, truncated XML); missing Nmap, permission errors, existing output files; timeouts; **cancellation** (event, Ctrl+C stop/skip/continue, stubborn process, forced kill); **concurrency limit, parallelism across hosts, same-host serialization** |
| `test_parser.py` | 31 | complete documents, tolerant parsing of missing fields, truncated/garbage/hostile XML, entity refusal, file errors, real Nmap fixtures, truncation at 60 different offsets |
| `test_session_integrity.py` | 19 | session folders and permissions, unique names, safe task folder names, JSON round trip, listing; `session.xml` structure and file references; SHA-256 verification; tamper/deletion detection; read-only originals; reports never modify originals |
| `test_reports.py` | 26 | HTML for mixed outcomes (completed, skipped, failed, timed out, partial), escaping of hostile content, no external resources, no invented scores, findings only from script wording, rebuild from saved session |
| `test_cli.py` | 104 | scripted terminal sessions: menus, every confirmation, public/large-range prompts, profile and NSE selection syntax, custom profiles, timing, run options, plan review (removed tasks stay as skipped), duplicates, root handling, failure handling, settings, previous sessions, entry point and missing Nmap, **no headless option exists** |
| `test_utils_models.py` | 20 | atomic writes, hashing, ownership hand-back, XML-safe text, logging, colour, data classes |
| `test_live_localhost.py` | 6 | (optional) real Nmap on loopback: every profile accepted by Nmap's option parser, connect scan finds a local web server, closed port, NSE task on its own, real timeout with partial output, SYN scan as root |
| `test_static_and_docs.py` | 22 | source-code safety (no `shell=True`, `eval`, `os.system`; argument lists only; standard library only; subprocess confined to three modules; Python 3.10 syntax), launchers, and that README, PROFILES.md, TESTING.md and DEBUGGING.md match the code (counts, flags, settings, modules, file names, test references) |
| `test_report_js.py` | 2 | (optional) report JavaScript in jsdom: 21 behaviour checks |

Total: see section 5. Many tests use `subTest`, so the number of individual checks is much higher (for example, 156 profiles are checked one by one).

## 4. Requirement traceability

| Phase 3 requirement | Where it is tested |
|---|---|
| mocked Nmap subprocesses | `tests/helpers.py` fake nmap; every `test_runner`, `test_reports`, `test_cli` case |
| all 156 profiles, argument generation | `test_profiles` (structure, options, planner, fake-Nmap execution), `test_live_localhost` (real option parser) |
| target validation | `test_targets`, `test_customargs`, `test_cli.SingleHostFlow` |
| task scheduling, concurrency limits, same-host locking | `test_planner.Chunking`, `test_planner.SameHostLocking`, `test_runner.ConcurrencyAndLocking` |
| NSE independent from profiles | `test_planner.NseIndependentFromProfiles`, `test_cli.NseSelection.test_nse_only_session_runs_without_any_profile` |
| XML parsing | `test_parser` |
| `session.xml` references, SHA-256, read-only originals | `test_session_integrity` |
| HTML, skipped, failed, timed-out, partial results | `test_reports`, `test_cli.PlanReviewBehaviour` |
| cancellation | `test_runner.Cancellation`, `test_cli.FailureHandling.test_ctrl_c_prompt_choices` |
| missing Nmap, permission errors, malformed XML, existing output files | `test_runner.FailureModes`, `test_cli.EntryPoint`, `test_cli.FailureHandling` |
| no scan without explicit confirmation | `test_runner.ConfirmationGate`, `test_cli.NothingRunsWithoutConfirmation` |
| no `shell=True` / safe arguments | `test_runner.SafeSubprocessUse`, `test_static_and_docs.StaticSafety` |
| README / PROFILES.md match the code | `test_static_and_docs.Documentation` |

## 5. Results at release

| Run | Command | Result |
|---|---|---|
| Default suite as root | `python3 -m unittest discover` | **428 tests, 0 failures, 0 errors**; 11 skipped (6 live, 2 jsdom, 3 that need a non-root user) |
| Default suite as normal user | `runuser -u nobody -- python3 -m unittest discover` | **428 tests, 0 failures, 0 errors**; 9 skipped (6 live, 2 jsdom, 1 that needs root) |
| Everything enabled (root, real Nmap 7.94 on loopback, jsdom) | `NMAPFLOW_LIVE_TESTS=1 NMAPFLOW_JSDOM=... python3 -m unittest discover` | **428 tests, 0 failures, 0 errors**; 3 skipped (the non-root-only ones) |
| Live tests alone | `NMAPFLOW_LIVE_TESTS=1 python3 -m unittest tests.test_live_localhost` | 6 tests, 0 failures |
| Report JavaScript (jsdom) | `NMAPFLOW_JSDOM=... python3 -m unittest tests.test_report_js` | 2 tests (21 behaviour checks), 0 failures |
| Line + branch coverage of `nmapflow/` | `coverage run --branch --source=nmapflow -m unittest discover` | **96 %** (3140 statements, 1184 branches) |
| Static analysis | `python3 -m pyflakes nmapflow nmapflow.py` | clean |

(The skip counts depend on whether you are root and whether the optional tools are installed. Skipped is not failed.)

Bugs found and fixed while writing these tests: see section 7.

## 6. Developer-only extras (not needed to run the tool)

```bash
pip install --break-system-packages pyflakes coverage
python3 -m pyflakes nmapflow tests
python3 -m coverage run --branch --source=nmapflow -m unittest discover && python3 -m coverage report -m
```

## 7. Bugs found by the test suite and fixed

| # | Bug | Found by | Fix |
|---|---|---|---|
| 1 | Pipe file descriptors of finished Nmap processes were not closed (a leak that grows with every scan) | `ResourceWarning` while running all 156 profiles | streams closed after the reader threads finish |
| 2 | Control characters in scan or error text made `session.xml` not well-formed | `test_xml_is_well_formed_even_with_hostile_text` | illegal XML characters removed from every XML and HTML value |
| 3 | EOF (closed terminal) at the Ctrl+C prompt raised an exception through the executor and left scans unattended | `test_ctrl_c_prompt_choices` | EOF or a second Ctrl+C now means "stop safely"; a crashing callback does too |
| 4 | Cancelling through the executor's cancel flag did not stop queued scans from starting or mark the session interrupted | `test_cancelled_session_is_flagged` | an external cancel is handled exactly like Ctrl+C "stop" |
| 5 | Rejected custom arguments were printed without the "Rejected:" prefix (`ArgError` is a `ValueError`, caught by the wrong branch) | `test_custom_arguments_are_validated` | exception order corrected |
| 6 | No limit on the number of target entries; warnings repeated every time units were recomputed | review while writing `test_targets` | 65,536-entry limit; warnings de-duplicated |
| 7 | "Hosts per task" on a huge range would expand millions of addresses | review while writing `test_planner` | bounded; falls back to automatic splitting with a warning |
| 8 | Skipping every task for lack of root silently returned to the menu | review while writing `test_cli` | explicit message |
| 9 | Task folder names contained runs of dashes (`ports---SYN`) | `test_slugify` | repeated dashes collapsed |

## 8. Local-lab workflow

**Rule: scan only machines you own or are explicitly allowed to test.** The lab below uses your own computer and, optionally, a
private network you control. Nothing in the automated tests needs any of it.

### 8.1 Localhost lab (recommended first step)

1. Start a throw-away web server that listens on loopback only:

   ```bash
   mkdir -p /tmp/lab && cd /tmp/lab && echo hello > index.html
   python3 -m http.server 8080 --bind 127.0.0.1 &
   ```

2. Run the tool and scan `127.0.0.1` only:

   ```bash
   cd nmapflow
   python3 nmapflow.py --reports-dir /tmp/lab_reports
   ```

   Keystrokes (the text after `>` is what you type):

   ```text
   Select: 1                                     (Single host)
   Target: 127.0.0.1
   Targets to EXCLUDE: <Enter>
   Type AUTHORIZED to confirm: AUTHORIZED
   profiles> custom -> 1 -> tcp -> 2 -> 22,8080 -> -sV      (a custom connect scan of two ports)
   profiles> done
   Add NSE scripts? y     nse> 6,7,11     nse> done        (http-title, http-headers, http-security-headers)
   Timing [T3]: <Enter>
   Change any of these for this run? <Enter>
   Type RUN to start: RUN
   ```

3. Expected result (taken from a real run on Ubuntu 24.04 with Nmap 7.94):

   ```text
   [1/2] START  Custom TCP -sT ports 22,8080
          command: /usr/bin/nmap -sT -p 22,8080 -sV -T3 -n -oX reports/.../scan.xml -oN reports/.../scan.nmap --stats-every 10s -v --reason 127.0.0.1
   [1/2] COMPLETED  (7s) | hosts up: 1/1 | open ports: 1

   [2/2] START  NSE scripts (TCP): http-title, http-headers, http-security-headers
   [2/2] COMPLETED  (6s) | hosts up: 1/1 | open ports: 1
   SESSION FINISHED  2 completed
   HTML report:        reports/2026-11-06_08-54-55/report.html
   ```

   Inside the report: `127.0.0.1` is up; `8080/tcp` is open (`http`, `SimpleHTTPServer 0.6`); `22/tcp` is closed (so it is not listed
   as open); `http-title` reports `Directory listing for /`; XML integrity shows `verified` for both scans.

4. Try the failure paths on purpose:

   * Press **Ctrl+C** during a slow scan (for example a custom `-sT -p-` at `T1`): choose `s`; the scan is marked `cancelled`, partial output is
     kept and the report says it is incomplete.
   * Pick an ACK profile (number 1) **without sudo** and answer `s`: the task is recorded as `skipped` with the reason.
   * At the plan review type `r 1` to remove a task: it stays in the report as `skipped`.
   * Edit a saved `scan.xml` (`chmod u+w`, append a comment), then choose menu 4 and open the session: the integrity column shows `MISMATCH`.

5. Stop the server: `kill %1`.

### 8.2 Private lab (optional)

Use an isolated network, for example a VirtualBox/VMware **host-only** network containing Kali and one or two machines you own
(a Linux VM running `apache2` or `openssh-server`, or an intentionally vulnerable VM such as Metasploitable that you downloaded yourself).
Checklist before scanning:

* The lab network has no route to the Internet or to production systems.
* You know every address in it (`ip -4 addr` on Kali shows the subnet; use menu 3, **Whole local network**, and pick that subnet).
* You are comfortable with the machines being slowed or crashing (older embedded or fragile services can react badly to scans; keep `T3`).
* Start with `Host discovery -> ping sweep` (profile 11), then `TCP top 1000`, then add version detection, then NSE bundles.
* Do not enable `T5` or full UDP scans (profiles 3 and 8 take hours) until you have measured how long a top-100 UDP scan takes.

### 8.3 Example input and expected output (unit level)

Target parsing:

| Input | Result |
|---|---|
| `192.168.10.2 192.168.10.5 192.168.10.20` | three targets, in that order |
| `192.168.10.2-5` | four targets `.2` to `.5` |
| `10.0.0.5/24` | one CIDR target, normalised to `10.0.0.0/24` |
| `Example.COM` | hostname `example.com` |
| `10.0.0.1; reboot`, `$(id)`, `-iL`, `999.1.1.1`, `10.0.0.0/7` | rejected with a reason, never scanned |

Profile arguments (`python3 nmapflow.py --show-profile N`):

| Number | Nmap arguments (before the options the tool adds) |
|---|---|
| 1 | `-sA -p-` |
| 4 | stage 1 `-sS -p-`, stage 2 `-sU --top-ports 1000` |
| 5 | `-sA --top-ports 1000 -sV` (warning: nothing to probe) |
| 7 | `-sS --top-ports 1000 -sV -O` |
| 9 | `-sT -p-` |

The tool then appends `-T<n>`, `-n`/`-Pn`/`-6` as needed, `--exclude ...`, `-oX <file> -oN <file> --stats-every 10s -v --reason` and the targets.

## 9. Final feature checklist

See the table in the project `README.md`, section "Feature checklist". Every row names the module that implements it and the test that checks it.
