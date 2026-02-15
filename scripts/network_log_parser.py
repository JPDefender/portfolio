#!/usr/bin/env python3
"""
Network Log Parser - Troubleshooting Tool
Author: softmetapod

Parses common network log formats (syslog, firewall, Windows event logs exported
as text) and surfaces connection failures, DNS issues, high-latency entries,
repeated denied connections, and other anomalies useful for troubleshooting.

Usage:
    python network_log_parser.py <logfile> [--output report.txt] [--top N]

Supported log patterns:
    - Syslog / rsyslog / journalctl output
    - iptables / firewall deny/drop entries
    - Windows netsh trace and event log exports
    - Generic timestamped connection logs
"""

import argparse
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime


# ---------------------------------------------------------------------------
# Regex patterns for common network log entries
# ---------------------------------------------------------------------------
PATTERNS = {
    "timestamp_syslog": re.compile(
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    ),
    "timestamp_iso": re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
    ),
    "ip_address": re.compile(
        r"\b(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
    ),
    "mac_address": re.compile(
        r"(?P<mac>([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})"
    ),
    "port": re.compile(
        r"(?:SPT|SRC_PORT|sport|srcport|DPT|DST_PORT|dport|dstport)[=: ]+(?P<port>\d{1,5})",
        re.IGNORECASE,
    ),
    "firewall_deny": re.compile(
        r"(DROP|DENY|BLOCK|REJECT|REFUSED)", re.IGNORECASE
    ),
    "firewall_allow": re.compile(
        r"(ACCEPT|ALLOW|PERMIT)", re.IGNORECASE
    ),
    "dns_query": re.compile(
        r"(query|lookup|resolve[ds]?)\s+.*?(?P<domain>[a-zA-Z0-9._-]+\.[a-zA-Z]{2,})",
        re.IGNORECASE,
    ),
    "dns_failure": re.compile(
        r"(NXDOMAIN|SERVFAIL|REFUSED|no\s+servers?\s+could\s+be\s+reached|"
        r"timed?\s*out|resolution\s+failed)",
        re.IGNORECASE,
    ),
    "connection_error": re.compile(
        r"(connection\s+(refused|reset|timed?\s*out|closed|failed)|"
        r"unreachable|no\s+route|link\s+down|interface\s+down)",
        re.IGNORECASE,
    ),
    "latency": re.compile(
        r"(?:time|latency|rtt|delay)[=: ]+(?P<ms>\d+\.?\d*)\s*ms",
        re.IGNORECASE,
    ),
    "packet_loss": re.compile(
        r"(?P<loss>\d+\.?\d*)%?\s*(?:packet\s+)?loss", re.IGNORECASE
    ),
    "dhcp_event": re.compile(
        r"(DHCPDISCOVER|DHCPOFFER|DHCPREQUEST|DHCPACK|DHCPNAK|DHCPRELEASE|DHCPDECLINE)",
        re.IGNORECASE,
    ),
}


class NetworkLogParser:
    """Parses a network log file and generates a troubleshooting summary."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.lines = []
        self.total_lines = 0
        self.denied_entries = []
        self.allowed_entries = []
        self.connection_errors = []
        self.dns_failures = []
        self.dns_queries = []
        self.high_latency = []
        self.packet_loss_entries = []
        self.dhcp_events = []
        self.source_ips = Counter()
        self.dest_ips = Counter()
        self.denied_ips = Counter()
        self.error_timeline = defaultdict(int)
        self.ports_targeted = Counter()

    # ----- loading --------------------------------------------------------
    def load(self):
        """Read log file into memory."""
        if not os.path.isfile(self.filepath):
            print(f"[ERROR] File not found: {self.filepath}")
            sys.exit(1)

        with open(self.filepath, "r", encoding="utf-8", errors="replace") as fh:
            self.lines = fh.readlines()
        self.total_lines = len(self.lines)
        print(f"[*] Loaded {self.total_lines} lines from {self.filepath}")

    # ----- parsing --------------------------------------------------------
    def parse(self):
        """Iterate through every line and classify it."""
        for line_num, line in enumerate(self.lines, start=1):
            self._extract_ips(line)
            self._extract_ports(line)
            self._check_firewall(line, line_num)
            self._check_dns(line, line_num)
            self._check_connection_errors(line, line_num)
            self._check_latency(line, line_num)
            self._check_packet_loss(line, line_num)
            self._check_dhcp(line, line_num)
            self._extract_timestamp_bucket(line)

    def _extract_ips(self, line):
        for match in PATTERNS["ip_address"].finditer(line):
            ip = match.group("ip")
            # Rough heuristic: first IP is often source, second is dest
            ips = PATTERNS["ip_address"].findall(line)
            if len(ips) >= 1:
                self.source_ips[ips[0]] += 1
            if len(ips) >= 2:
                self.dest_ips[ips[1]] += 1

    def _extract_ports(self, line):
        for match in PATTERNS["port"].finditer(line):
            self.ports_targeted[match.group("port")] += 1

    def _check_firewall(self, line, line_num):
        if PATTERNS["firewall_deny"].search(line):
            self.denied_entries.append((line_num, line.strip()))
            ips = PATTERNS["ip_address"].findall(line)
            for ip in ips:
                self.denied_ips[ip] += 1
        elif PATTERNS["firewall_allow"].search(line):
            self.allowed_entries.append((line_num, line.strip()))

    def _check_dns(self, line, line_num):
        if PATTERNS["dns_failure"].search(line):
            self.dns_failures.append((line_num, line.strip()))
        elif PATTERNS["dns_query"].search(line):
            self.dns_queries.append((line_num, line.strip()))

    def _check_connection_errors(self, line, line_num):
        if PATTERNS["connection_error"].search(line):
            self.connection_errors.append((line_num, line.strip()))

    def _check_latency(self, line, line_num):
        match = PATTERNS["latency"].search(line)
        if match:
            ms = float(match.group("ms"))
            if ms > 100:  # flag anything over 100 ms
                self.high_latency.append((line_num, ms, line.strip()))

    def _check_packet_loss(self, line, line_num):
        match = PATTERNS["packet_loss"].search(line)
        if match:
            loss = float(match.group("loss"))
            if loss > 0:
                self.packet_loss_entries.append((line_num, loss, line.strip()))

    def _check_dhcp(self, line, line_num):
        if PATTERNS["dhcp_event"].search(line):
            self.dhcp_events.append((line_num, line.strip()))

    def _extract_timestamp_bucket(self, line):
        """Group errors by hour for timeline analysis."""
        for pat_name in ("timestamp_iso", "timestamp_syslog"):
            match = PATTERNS[pat_name].search(line)
            if match:
                ts = match.group("timestamp")
                # Normalize to hour bucket
                hour = ts[:13] if pat_name == "timestamp_iso" else ts[:10]
                if PATTERNS["firewall_deny"].search(line) or PATTERNS["connection_error"].search(line):
                    self.error_timeline[hour] += 1
                break

    # ----- reporting ------------------------------------------------------
    def report(self, top_n=10):
        """Return a formatted troubleshooting report string."""
        sections = []
        border = "=" * 72

        sections.append(border)
        sections.append("  NETWORK LOG TROUBLESHOOTING REPORT")
        sections.append(f"  Source: {self.filepath}")
        sections.append(f"  Total lines parsed: {self.total_lines}")
        sections.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        sections.append(border)

        # --- Summary counts ---
        sections.append("\n[SUMMARY]")
        sections.append(f"  Firewall DENY/DROP entries : {len(self.denied_entries)}")
        sections.append(f"  Firewall ALLOW entries     : {len(self.allowed_entries)}")
        sections.append(f"  Connection errors          : {len(self.connection_errors)}")
        sections.append(f"  DNS failures               : {len(self.dns_failures)}")
        sections.append(f"  High-latency entries (>100ms): {len(self.high_latency)}")
        sections.append(f"  Packet-loss entries (>0%)  : {len(self.packet_loss_entries)}")
        sections.append(f"  DHCP events                : {len(self.dhcp_events)}")

        # --- Top denied IPs ---
        if self.denied_ips:
            sections.append(f"\n[TOP {top_n} IPs IN DENY/DROP ENTRIES]")
            for ip, count in self.denied_ips.most_common(top_n):
                sections.append(f"  {ip:<20} {count} hits")

        # --- Top source IPs ---
        if self.source_ips:
            sections.append(f"\n[TOP {top_n} SOURCE IPs]")
            for ip, count in self.source_ips.most_common(top_n):
                sections.append(f"  {ip:<20} {count} occurrences")

        # --- Top destination IPs ---
        if self.dest_ips:
            sections.append(f"\n[TOP {top_n} DESTINATION IPs]")
            for ip, count in self.dest_ips.most_common(top_n):
                sections.append(f"  {ip:<20} {count} occurrences")

        # --- Top targeted ports ---
        if self.ports_targeted:
            sections.append(f"\n[TOP {top_n} TARGETED PORTS]")
            for port, count in self.ports_targeted.most_common(top_n):
                sections.append(f"  Port {port:<10} {count} occurrences")

        # --- Error timeline ---
        if self.error_timeline:
            sections.append("\n[ERROR TIMELINE (errors per time bucket)]")
            for bucket in sorted(self.error_timeline):
                bar = "#" * min(self.error_timeline[bucket], 60)
                sections.append(f"  {bucket}  {self.error_timeline[bucket]:>5}  {bar}")

        # --- Connection errors (sample) ---
        if self.connection_errors:
            sections.append(f"\n[CONNECTION ERRORS — showing first {top_n}]")
            for line_num, entry in self.connection_errors[:top_n]:
                sections.append(f"  Line {line_num}: {entry[:120]}")

        # --- DNS failures (sample) ---
        if self.dns_failures:
            sections.append(f"\n[DNS FAILURES — showing first {top_n}]")
            for line_num, entry in self.dns_failures[:top_n]:
                sections.append(f"  Line {line_num}: {entry[:120]}")

        # --- High latency (sample) ---
        if self.high_latency:
            sections.append(f"\n[HIGH LATENCY ENTRIES — showing first {top_n}]")
            for line_num, ms, entry in sorted(self.high_latency, key=lambda x: -x[1])[:top_n]:
                sections.append(f"  Line {line_num} ({ms:.1f} ms): {entry[:120]}")

        # --- Packet loss (sample) ---
        if self.packet_loss_entries:
            sections.append(f"\n[PACKET LOSS ENTRIES — showing first {top_n}]")
            for line_num, loss, entry in sorted(self.packet_loss_entries, key=lambda x: -x[1])[:top_n]:
                sections.append(f"  Line {line_num} ({loss:.1f}% loss): {entry[:120]}")

        # --- DHCP events (sample) ---
        if self.dhcp_events:
            sections.append(f"\n[DHCP EVENTS — showing first {top_n}]")
            for line_num, entry in self.dhcp_events[:top_n]:
                sections.append(f"  Line {line_num}: {entry[:120]}")

        # --- Firewall deny sample ---
        if self.denied_entries:
            sections.append(f"\n[FIREWALL DENY/DROP SAMPLE — showing first {top_n}]")
            for line_num, entry in self.denied_entries[:top_n]:
                sections.append(f"  Line {line_num}: {entry[:120]}")

        sections.append("\n" + border)
        sections.append("  END OF REPORT")
        sections.append(border + "\n")

        return "\n".join(sections)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Parse network logs and generate a troubleshooting report."
    )
    parser.add_argument("logfile", help="Path to the network log file to parse")
    parser.add_argument(
        "--output", "-o",
        help="Write the report to a file instead of stdout",
        default=None,
    )
    parser.add_argument(
        "--top", "-n",
        help="Number of top entries to display per section (default: 10)",
        type=int,
        default=10,
    )

    args = parser.parse_args()

    log_parser = NetworkLogParser(args.logfile)
    log_parser.load()
    log_parser.parse()
    report = log_parser.report(top_n=args.top)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"[*] Report written to {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
