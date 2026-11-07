# nmapflow: debugging notes

## Where to look first

Every session folder (`reports/YYYY-MM-DD_HH-MM-SS/`) is a complete record:

| File | What it tells you |
|---|---|
| `session.log` | timestamped log of the whole session: scope, every command, every status change, exit codes |
| `session.json` | machine-readable record: scope, authorization, settings, every task with status, error text, exit code, hash |
| `tasks/NNN_.../command.txt` | the exact command that was run (copy it to reproduce a scan by hand) |
| `tasks/NNN_.../stderr.log` | what Nmap complained about (most failure reasons are here) |
| `tasks/NNN_.../stdout.log` | Nmap's live output, including progress lines |
| `tasks/NNN_.../scan.xml`, `scan.nmap` | Nmap's own result files (read-only, never edited) |
| `tasks/NNN_.../meta.json` | the task record as it was when the scan ended |

Reproduce one scan by hand (this runs the identical command, no shell games needed):

```bash
cat reports/2026-11-06_08-54-55/tasks/001_*/command.txt
# copy the line, change the -oX/-oN paths to /tmp/test.xml and /tmp/test.nmap, then run it
```

## Common problems

| Symptom | Likely cause | What to do |
|---|---|---|
| `Nmap was not found.` at start | Nmap is not installed or not on `PATH` | `sudo apt update && sudo apt install -y nmap`; or set `nmap_path` in `config.json` |
| `You requested a scan type which requires root privileges` in `stderr.log` | SYN/ACK/UDP/OS/traceroute need raw sockets | restart with `sudo python3 nmapflow.py` (the tool offers to skip such tasks when not root) |
| Reports and sessions are owned by root | an older folder was created by `sudo` | new sessions created under `sudo` are handed back to you (`SUDO_UID`); fix old ones with `sudo chown -R "$USER": reports` |
| `No host responded` | host is down, or it drops discovery probes (ping) | rerun with host discovery turned off (Run options, or profile with `-Pn`); check you are on the right network |
| Task `failed`: `Nmap output (XML) is incomplete` | Nmap was killed or crashed before it finished writing | look at `stderr.log`; the partial XML is kept and parsed in memory; rerun the task |
| Task `timed_out` | per-scan limit reached (`timeout_minutes`, default 240) | raise the limit or use a smaller scope; UDP all-ports scans can take many hours per host |
| UDP scan seems stuck | UDP has no handshake and targets rate-limit ICMP replies | normal; use top-100/top-1000 UDP first |
| `script not available and not run: ...` in the plan | the script is missing in your Nmap, or this Nmap labels it intrusive | `ls /usr/share/nmap/scripts/ | grep NAME`; the tool refuses banned categories by design |
| NSE menu says `unavailable` or `script.db not found` | Nmap's script database is missing | install the full package: `sudo apt install --reinstall nmap`; check `/usr/share/nmap/scripts/script.db` |
| `Rejected input (these will NOT be scanned)` | the entry is not a valid target (or looks like an Nmap option or shell text) | fix the entry; nothing was scanned |
| `Only N MB free` | fewer than 100 MB free in the output folder | free space or use `--reports-dir` |
| Subnet list is empty | no active IPv4 interface, or `ip` is missing | `sudo apt install iproute2`; or choose `m` and type a CIDR |
| IPv6 target skipped or fails | IPv6 is disabled on the machine | `nmap -6 -sT -p 80 ::1` by hand to check IPv6 support |
| Report shows `MISMATCH` | an original `scan.xml` changed after the scan | treat the result as untrusted; restore from backup or rescan |
| `Settings: ... using default` | invalid value in `config.json` | fix or delete the file; the message names the setting |
| Ctrl+C seems to do nothing for several seconds | the tool is waiting for Nmap to flush output (SIGINT, then SIGTERM after 8 s, then SIGKILL after 4 s more) | press Ctrl+C again at the prompt to force-stop |

## Running with more detail

```bash
python3 -m unittest discover -v                      # all tests, one line each
python3 -m unittest tests.test_runner -v             # just the runner
python3 -W error::ResourceWarning nmapflow.py        # surface leaked file descriptors while developing
python3 nmapflow.py --list-profiles | less           # see every profile and its exact arguments
python3 nmapflow.py --show-profile REQ-05-TCP-TOP1000-ACK-SV
```

To see what the tool would hand to Nmap without scanning, use the plan review screen and answer `b` (cancel). Nothing runs until you type `RUN`.

## Checking a result file by hand

```bash
python3 - <<'PY'
from pathlib import Path
from nmapflow.parser import parse_file
r = parse_file(Path("reports/2026-11-06_08-54-55/tasks/001_Custom-TCP-sT-ports-22-8080/scan.xml"))
print(r.complete, r.repaired, r.errors)
for h in r.hosts:
    print(h.address, h.state, [(p.number, p.protocol, p.state, p.service) for p in h.ports])
PY
sha256sum reports/*/tasks/*/scan.xml                 # compare with "xml_sha256" in session.json
```

## Adding a profile or script

* Profile: edit `nmapflow/profiles.py` (the generator functions), run `python3 nmapflow.py --export-catalog docs/PROFILES.md`,
  then the test suite. Tests check unique IDs, valid options, banned options, guard expressions and the README/PROFILES.md count.
* NSE script: add a row to `_SCRIPT_ROWS` in `nmapflow/nse.py` (and to a bundle if wanted). It is checked against your installed Nmap's
  `script.db` at startup; scripts labelled intrusive, dos, exploit, brute, fuzzer, external or broadcast are refused automatically.
