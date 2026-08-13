# ssh-log-analyzer

Detects SSH brute-force attempts in standard Linux `auth.log` files. Groups
failed password attempts by source IP and flags any IP with 5+ failures
within a 10-minute sliding window (configurable). Python stdlib only at
runtime; pytest for tests.

## Install

```bash
pip install -e ".[dev]"
```

## Usage

```bash
# Analyze a log file
ssh-log-analyzer /var/log/auth.log

# Read from stdin
cat /var/log/auth.log | ssh-log-analyzer -

# JSON output, custom threshold/window
ssh-log-analyzer /var/log/auth.log --format json --threshold 3 --window 5

# Exit with status 2 if any IP is flagged (useful in CI/alerting)
ssh-log-analyzer /var/log/auth.log --fail-on-detection
```

Run `ssh-log-analyzer --help` for the full flag list.

## Generating sample data

`ssh-log-gen-sample` produces a realistic synthetic `auth.log`: normal user
traffic, background internet scanner noise, "near miss" IPs that stay just
under the detection threshold, and injected attacker IPs with dense
brute-force bursts.

```bash
ssh-log-gen-sample -o sample.log --seed 42 --manifest manifest.json
ssh-log-analyzer sample.log
```

The manifest lists which IPs were injected as attackers/legit/near-miss, so
you can cross-check the analyzer's report against ground truth.

## Known limitations

- Syslog auth.log timestamps have no year. `--year` defaults to the current
  year; logs spanning a December→January boundary need to be split and
  analyzed with two separate `--year` runs.
- Only `Failed password` sshd lines are parsed (the standard brute-force
  signature); other auth-failure line formats (e.g. PAM-only logging,
  journald-forwarded logs without a hostname field) are not recognized in v1.

## Tests

```bash
pytest -v
```
