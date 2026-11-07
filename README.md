# Sec

A C++ endpoint protection tool I'm building with macOS as the main target. It's still a prototype. It does two things:

- **File scanning**: SHA-256 hash lookups, byte-pattern signatures and static PE analysis to find malicious files.
- **Behavior detection**: follows process execution, file writes and network connections together, and flags the chain of intrusion → persistence → outbound C2 traffic.

Both only **alert**. Nothing gets blocked or deleted automatically (there's an auto-quarantine option, but it's off by default).

The project started as a file scanner. A lot of real attacks are easier to catch by looking at what a process does than by looking at a single file, so most of the current work is on the behavior side.

## What works today

- macOS menu bar app: an icon shows the state, and clicking it opens a list of detections
- Real-time folder watching (FSEvents) on Downloads, Desktop and Documents by default
- Hash DB, signature and PE heuristic scanning, plus quarantine
- Behavior engine with about 43 built-in rules, extendable or overridable with JSON, plus an allowlist for known-good activity
- Alerts carry the recent activity of the process chain, and the files involved are hashed and run through the file scanner
- `behavior-replay`, a command that feeds recorded events through the engine
- `sec-sensord`, a root daemon that collects live events (eslogger + TCP socket polling), runs the engine and writes alerts
- The menu bar app shows those alerts (red icon, notification, list window) and whether the sensor is running

## What doesn't work yet

- **The live sensor code hasn't run on a real Mac yet.** `sec-sensord`, the libproc socket polling and the menu bar integration are written and the portable parts are tested on Linux, but the macOS-specific parts (libproc, `main.mm`, the LaunchDaemon install) are unverified. Expect a round of fixes.
- **The eslogger parser hasn't been checked against real output.** It follows the JSON layout I expect from `eslogger`, but I haven't verified it on a real Mac yet (see "Checking against eslogger" below).
- No DNS visibility. Without a Network Extension there's no source for DNS queries, so the DNS rules only run on replayed events.
- Socket polling sees a connection only if it lives longer than the poll interval (1 second by default), and it only reports new connections, not ones that already existed when the sensor started.
- At start-up the sensor takes a snapshot of running processes (path, parent, arguments, code signature) so that processes launched before it are not "unknown". That snapshot code is macOS-only and unverified, like the rest of the live sensor. Signatures are read without full validation, and "anchor apple" is used as the stand-in for "platform binary", so Apple-signed apps such as Xcode count as platform binaries here but not in eslogger's view.
- **No pre-execution blocking.** FSEvents tells you about a file after it exists, so file scanning is detect-after-the-fact. Blocking before execution needs the EndpointSecurity entitlement, which requires Apple's approval, so it isn't used here.
- No Mach-O or ELF static analysis. Those files only get hash and pattern checks.
- Quarantined files are obscured with XOR, not encrypted.
- Windows: the core library is kept portable, but the Windows service (`src/service`) hasn't been build-tested.

## Layout

```
src/common     SHA-256 (own implementation), logging, config, JSON parser, utilities
src/scanner    hash DB, PE analysis, scan engine, quarantine
src/agent      agent core, real-time scan queue, detection store
src/behavior   behavior detection: event model, process tree, rule engine, eslogger parser, alert store
src/sensor     live sensors: sensor service, eslogger runner, socket polling, start-up process snapshot, alert enricher (non-Windows)
src/sensord    sec-sensord daemon
src/monitor    FSEvents file watcher (macOS only)
src/macapp     menu bar app (macOS only)
src/cli        sec-cli
src/agentd     sec-agentd (foreground agent)
src/service    Windows service (Windows only)
packaging/     app bundle and login-item scripts for macOS
config/        sample configs
data/          sample hash list, replay scenarios for behavior detection
tests/         unit tests
```

## Building

Written for macOS. You need the Xcode command line tools (a clang with C++20), CMake and Ninja.

```sh
xcode-select --install
brew install cmake ninja

cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

This produces `sec-cli`, `sec-agentd`, `sec-sensord` and `sec-menubar`. If CMake complains about a different cache path, you probably copied a `build` folder from another machine. Delete it and configure again.

The core also builds on Linux with the same commands (without the menu bar app and FSEvents). Windows should work with Visual Studio and CMake, but I haven't tested it as much as macOS.

On Linux the test suite (1300 checks) passes under ASan/UBSan and TSan. I haven't run the behavior tests on a Mac yet.

## Menu bar app

```sh
packaging/macos/make_app.sh          # creates build/Sec.app (ad-hoc signed)
open build/Sec.app                   # shield icon shows up in the menu bar
packaging/macos/install_login.sh     # start at login (--uninstall to remove)
```

- Icon: check shield = fine, red shield = new detection, slashed shield = paused or watcher failed
- Menu: status, open detection list, full scan, pause/resume, open data folder, quit
- Watched folders default to `~/Downloads`, `~/Desktop` and `~/Documents`. Change them with `watch_paths` (see `config/sec.conf.mac.sample`).
- macOS will ask for folder access on first launch. Allow it, otherwise nothing gets watched.
- Data lives in `~/Library/Application Support/SecEPP`

A file is scanned once it has stopped changing for 1.5 seconds. This avoids scanning files that are still being downloaded.

## CLI

```sh
sec-cli scan ~/Downloads --hashdb hashes.txt --quarantine
sec-cli hash <file>
sec-cli pe <file.exe>
sec-cli quarantine list
sec-cli quarantine restore <id>
```

### How files are scanned

1. SHA-256 hash DB. `hashes.txt` takes lines in the form `<sha256> [name]`.
2. Byte patterns. The EICAR test string is built in, and you can add more with `ScanEngine::add_pattern()`.
3. Static PE heuristics: packer section names, high-entropy executable sections, writable+executable sections, API combinations typical of injection, keyloggers and downloaders. Points are added up; 40 or more is *suspicious*, 90 or more is *malicious*.

Heuristics can produce false positives, which is why `auto_quarantine` is off. Tune the thresholds against a set of clean files before relying on it.

## Behavior detection

### Running the live sensor (macOS 13+)

The sensor needs root, because `eslogger` only works as root. It runs as a LaunchDaemon and the menu bar app (which runs as you) reads its output.

```sh
cmake --build build
sudo packaging/macos/install_sensord.sh
```

Then give the binary Full Disk Access: System Settings → Privacy & Security → Full Disk Access → `+` → `/usr/local/libexec/sec/sec-sensord` (press Cmd+Shift+G to type the path). If it still fails, add `/usr/bin/eslogger` the same way. Restart it afterwards:

```sh
sudo launchctl kickstart -k system/com.sec.epp.sensord
cat "/Library/Application Support/SecEPP/sensor_status.txt"
```

`sensor_status.txt` shows whether eslogger and the socket poller are running, how many events were processed, and the last error. The menu bar app shows the same state in its menu. Every rebuild changes the ad-hoc signature, so macOS may ask for the permission again.

Files in `/Library/Application Support/SecEPP/`:

- `behavior_alerts.tsv`: alerts, one per line (the menu bar app reads this)
- `behavior_rules.json`: optional, your rules and allowlist, merged over the built-in ones
- `ioc.json`: optional IOC list
- `hashes.txt`: optional hash DB; files an alert points to are checked against it (or pass `--hashes FILE`)
- `logs/sensord.log`
- `logs/sensord-events.log`: one line per event, only with `--verbose` (reset at every start, capped at 64 MB)

If the menu bar app should read from another folder, set `behavior_dir` in its `sec.conf`. Remove the sensor with `sudo packaging/macos/install_sensord.sh --uninstall`.

Useful options: `--verbose` (per-event trace, for debugging), `--no-snapshot` (skip the start-up process snapshot), `--no-scan` (don't hash or scan the files an alert points to), `--hashes FILE`. To watch it live: `sudo tail -f "/Library/Application Support/SecEPP/logs/sensord.log"`.

You can also run it by hand to try it out: `sudo build/src/sensord/sec-sensord --console --data-dir /tmp/sec-test`, or feed it recorded events with `--source stdin < events.jsonl`.

### How it works

```
sensor → normalized events → process tree → rules / correlation → warning or critical alert
```

Every process accumulates a score and a set of tags, and a child inherits both from its parent. So a chain like "document app spawns a shell → shell downloads something into /tmp → it gets executed → a LaunchAgent is written → it connects out" adds up, even though each step alone is only mildly suspicious.

- Warning at 60 points, critical at 100.
- When a new stage (persistence, C2, and so on) first shows up on a process chain, it alerts again even if the level didn't change.
- A rule counts at most once per process.
- Each rule carries a MITRE ATT&CK technique ID.
- An alert includes up to 12 recent events of the processes in the chain (`T-3.2s  curl(900)  exec ...`) and, for unsigned or staged executables on the chain, their SHA-256 and the scanner's verdict. If the scanner calls one of them malicious the alert becomes critical.

Features rules can depend on:

- `recent_download_exec`: running a file that was just downloaded or written (files written by compilers are ignored)
- `beaconing`: 6+ connections to the same destination at regular intervals, with a mean gap of at least 5 seconds
- `ioc_match`: destination IP or domain is in your IOC list
- `dga_like`, `tunnel_like`: domains that look generated, DNS queries that look like tunneling
- `egress_violation`: connection to a destination outside the allowlist (off by default)

### Replaying events

```sh
build/src/cli/sec-cli behavior-replay data/scenarios/c2_chain.jsonl
build/src/cli/sec-cli behavior-replay data/scenarios/benign_dev.jsonl
```

The first is a simulated intrusion → persistence → C2 chain and produces several warning and critical alerts. The second is ordinary developer activity (compiling, running the result, using curl) and should produce none. It's there as a false-positive check.

Options: `--rules <file>`, `--ioc <file>`, `--json`. Pass `-` to read from stdin.

### Writing rules

`sec-cli behavior-rules` prints the built-in rules. Pass your own file with `--rules`: rules with an existing `id` replace the built-in one, new ids are added. Unknown keys are an error instead of being silently ignored.

```json
{
  "rules": [
    {
      "id": "my.nc_listen",
      "title": "nc started in listen mode",
      "event": "exec",
      "score": 50,
      "tag": "staged",
      "when": { "name_any": ["nc", "ncat"], "args_contains_any": [" -l"] }
    }
  ]
}
```

`event` is one of `exec`, `file`, `net`, `dns`. Inside `when`, different conditions are ANDed and the entries of a single list are ORed. The available conditions are listed in `src/behavior/rules.h`.

An egress allowlist goes in the same file:

```json
{
  "egress": {
    "enabled": true,
    "applies_to": ["myagent"],
    "allow": ["203.0.113.0/24", "*.corp.example"],
    "per_process": { "myagent": ["198.51.100.5"] }
  }
}
```

#### Allowlist

Known-good activity can be skipped with an `allowlist` in the same file. A matching entry makes the rule not fire at all, so it adds no score and sets no tag. `sensor_status.txt` counts these as `suppressed`.

```json
{
  "allowlist": [
    {
      "id": "corp-update-agent",
      "note": "signed by our team, talks to many hosts",
      "rules": ["mac.net.*"],
      "when": { "team_id_any": ["ABCDE12345"] }
    }
  ]
}
```

- `rules`: rule ids, a trailing `*` makes it a prefix. Leave it out to cover every rule.
- `event`: optional, `exec|file|net|dns`.
- `when`: the same conditions as in a rule, plus `team_id_any`, `signing_id_any`, `remote_ip_any` (IP or CIDR) and `remote_host_any` (also matches DNS names). `requires_tag_any` and `requires_feature_any` aren't allowed here.
- An entry needs at least one of `rules`, `event` or `when`; otherwise it would allow everything and the file is rejected.

`config/behavior_rules.example.json` has more examples. A rule that is allowed for one process can still fire for another, and the other rules on the same event are unaffected.

The IOC file looks like `{"ips": ["203.0.113.0/24"], "hosts": ["*.bad.example"]}`.

### Checking against eslogger

On macOS 13 or later, `eslogger` can stream process and file events. It needs root and Full Disk Access for your terminal.

```sh
sudo eslogger exec fork exit create rename close | head -n 50 > /tmp/es.jsonl
build/src/cli/sec-cli behavior-replay /tmp/es.jsonl
```

If `parse_errors` at the end isn't 0, the parser doesn't match the real output. The format can differ a bit between macOS versions.

`eslogger` has no network events, so connections need a separate sensor (for example polling the socket list). A proper version would use EndpointSecurity plus a Network Extension.

Input can be either eslogger JSON lines or this project's normalized JSONL; the format is detected automatically. For the normalized format, see the comment at the top of `src/behavior/es_parser.h` and the examples in `data/scenarios/`.

## Quick detection test

None of these do anything harmful. Watch `sudo tail -f "/Library/Application Support/SecEPP/logs/sensord.log" | grep --line-buffered ALERT` in another terminal.

```sh
bash -c 'echo test /dev/tcp/127.0.0.1/9'                          # reverse-shell pattern, warning
sqlite3 -readonly /tmp/tcc.db "select 1;"                         # TCC database edit, warning
osascript -e 'return "do shell script with administrator privileges"'   # warning
curl --limit-rate 100 -s -o /tmp/sec_test.txt https://example.com # download, then connection, warning
DYLD_INSERT_LIBRARIES=/tmp/none.dylib /usr/bin/true               # 40 points: no alert by itself
rm -f /tmp/tcc.db /tmp/sec_test.txt
```

The replay scenarios `c2_chain`, `credential_theft` and `dyld_injection` in `data/scenarios/` show the combined chains without a sensor.

## Next up

- Run the sensor on a real Mac and fix what breaks (eslogger JSON layout, libproc, permissions)
- DNS visibility through a Network Extension (or at least the unified log)
- Ship alerts to a SIEM (syslog / JSON file / webhook)
- Rule regression tests: "this event file must produce exactly these alerts" next to each rule
- Validate rules against real attack simulations (Atomic Red Team and similar) and cut down false positives
- Encrypt quarantined files (AES-GCM)
- Mach-O analysis
- Windows service build check, Authenticode verification

## License

Not decided yet. A `LICENSE` file will be added before this goes public.
