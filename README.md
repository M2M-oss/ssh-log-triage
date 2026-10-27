# SSH Log Triage

A small Python tool that reads a Linux SSH auth log and flags the kinds of activity a SOC analyst looks for first. Each finding is mapped to a MITRE ATT&CK technique and given a severity.

## What it detects

| Detection | Severity | ATT&CK | Logic |
|---|---|---|---|
| Brute force | HIGH | T1110 | 5+ failed logins from one IP within 120 seconds |
| Password spraying | MEDIUM | T1110.003 | One IP failing against 5+ different usernames |
| Success after failures | CRITICAL | T1078 | A login succeeds from an IP after a run of failures |

The thresholds are command-line options, so they can be tuned to cut false positives.

## How to run

Requires Python 3.8+ and no extra packages.

```bash
python3 triage.py sample_auth.log --year 2026
```

Options: `--threshold`, `--window`, `--spray-users`, `--year` (syslog lines have no year, so it defaults to the current one).

## Example output

```
Parsed 24 login attempts, 3 finding(s)

[CRITICAL] Success after failures (T1078) from 203.0.113.45
           'admin' logged in at 02:20:50 after 14 failures
[HIGH    ] Brute force (T1110) from 203.0.113.45
           14 failed logins, 5+ within 120s
[MEDIUM  ] Password spraying (T1110.003) from 198.51.100.23
           6 different usernames tried
```

## Investigation notes

`sample_auth.log` is synthetic data with three scenarios. The IPs come from the reserved documentation ranges, so they are not real hosts.

- **203.0.113.45** fired 14 failed logins against `admin` in about 40 seconds, then logged in successfully. This is the most serious finding because the brute force probably worked. In a real SOC this would mean checking what `admin` did after login, then resetting credentials and isolating the host.
- **198.51.100.23** tried six usernames, one attempt every 90 seconds. It never trips the brute-force rule because it stays under the rate threshold, which is why the spraying rule counts distinct usernames instead.
- **192.0.2.10** (`maria`) had one typo before a successful login. Correctly not flagged.

## Limitations and next steps

- Only parses `sshd` password events. Key-based logins and `pam` logs are ignored.
- Groups by source IP, so attackers rotating IPs would slip through.
- Next steps: read real logs from a lab VM, add GeoIP and known-bad IP enrichment, output JSON for a SIEM, and write the same detections as Splunk searches.

## Files

- `triage.py` - the detection script
- `sample_auth.log` - synthetic log with three scenarios
