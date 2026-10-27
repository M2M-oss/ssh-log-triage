#!/usr/bin/env python3
"""SSH log triage: flag brute force, password spraying, and success-after-failure.

Reads a Linux auth log (syslog format) and prints findings mapped to MITRE ATT&CK.
Usage: python3 triage.py sample_auth.log
"""
import argparse
import re
from collections import defaultdict, deque
from datetime import datetime

LINE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s\S+\ssshd\[\d+\]:\s"
    r"(?P<result>Failed|Accepted)\spassword\sfor\s(?:invalid user\s)?"
    r"(?P<user>\S+)\sfrom\s(?P<ip>\S+)"
)


def parse(path, year):
    """Return a list of (timestamp, result, user, ip) for each login attempt."""
    events = []
    with open(path) as f:
        for line in f:
            m = LINE.match(line)
            if m:
                ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S")
                events.append((ts, m["result"], m["user"], m["ip"]))
    return events


def detect(events, threshold, window, spray_users):
    """Group attempts by source IP and apply three simple detections."""
    by_ip = defaultdict(list)
    for event in events:
        by_ip[event[3]].append(event)

    findings = []
    for ip, attempts in by_ip.items():
        fails = [e for e in attempts if e[1] == "Failed"]

        # 1. Brute force: `threshold` failures inside a `window`-second span.
        recent = deque()
        for ts, *_ in fails:
            recent.append(ts)
            while (ts - recent[0]).total_seconds() > window:
                recent.popleft()
            if len(recent) >= threshold:
                findings.append(("HIGH", "Brute force", "T1110", ip,
                                 f"{len(fails)} failed logins, {threshold}+ within {window}s"))
                break

        # 2. Password spraying: one IP failing against many different usernames.
        users = {e[2] for e in fails}
        if len(users) >= spray_users:
            findings.append(("MEDIUM", "Password spraying", "T1110.003", ip,
                             f"{len(users)} different usernames tried"))

        # 3. Success after failures: a login worked after a run of failures.
        failed_so_far = 0
        for ts, result, user, _ in attempts:
            if result == "Failed":
                failed_so_far += 1
            elif failed_so_far >= threshold:
                findings.append(("CRITICAL", "Success after failures", "T1078", ip,
                                 f"'{user}' logged in at {ts:%H:%M:%S} after {failed_so_far} failures"))
                break
    return findings


def main():
    parser = argparse.ArgumentParser(description="Triage SSH auth logs.")
    parser.add_argument("logfile")
    parser.add_argument("--threshold", type=int, default=5, help="failures that count as brute force")
    parser.add_argument("--window", type=int, default=120, help="seconds for the brute-force window")
    parser.add_argument("--spray-users", type=int, default=5, help="distinct usernames that count as spraying")
    parser.add_argument("--year", type=int, default=datetime.now().year, help="syslog lines have no year")
    args = parser.parse_args()

    events = parse(args.logfile, args.year)
    findings = detect(events, args.threshold, args.window, args.spray_users)

    print(f"Parsed {len(events)} login attempts, {len(findings)} finding(s)\n")
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    for sev, name, technique, ip, detail in sorted(findings, key=lambda f: order[f[0]]):
        print(f"[{sev:8}] {name} ({technique}) from {ip}\n           {detail}")


if __name__ == "__main__":
    main()
