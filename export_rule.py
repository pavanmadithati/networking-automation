#!/usr/bin/env python3
"""Fetch SCM security rules and export them to CSV."""

import os
import csv
import json
import argparse
import requests
from dotenv import load_dotenv

load_dotenv()


def get_access_token() -> str:
    resp = requests.post(
        "https://auth.apps.paloaltonetworks.com/am/oauth2/access_token",
        data={
            "grant_type": "client_credentials",
            "client_id": os.getenv("SCM_CLIENT_ID"),
            "client_secret": os.getenv("SCM_CLIENT_SECRET"),
            "scope": f"tsg_id:{os.getenv('SCM_TSG_ID')}"
        }
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def fetch_rules(token: str, folder: str, position: str, limit: int) -> list:
    resp = requests.get(
        "https://api.sase.paloaltonetworks.com/sse/config/v1/security-rules",
        headers={"Authorization": f"Bearer {token}"},
        params={"folder": folder, "position": position, "limit": limit}
    )
    resp.raise_for_status()
    return resp.json().get("data", [])


def rule_to_csv_row(rule: dict) -> dict:
    return {
        "rule_name":           rule.get("name", ""),
        "description":         rule.get("description", ""),
        "source_zone":         ";".join(rule.get("from", [])),
        "destination_zone":    ";".join(rule.get("to", [])),
        "source_address":      ";".join(rule.get("source", [])),
        "destination_address": ";".join(rule.get("destination", [])),
        "application":         ";".join(rule.get("application", [])),
        "service":             ";".join(rule.get("service", [])),
        "action":              rule.get("action", ""),
        "log_start":           "yes" if rule.get("log_start") else "no",
        "log_end":             "yes" if rule.get("log_end") else "no",
        "profile_group":       ";".join(rule.get("profile_setting", {}).get("group", [])),
        "tags":                ";".join(rule.get("tag", [])),
    }


def parse_args():
    parser = argparse.ArgumentParser(description="Export SCM security rules to CSV")
    parser.add_argument("--output", default="exported_rules.csv", help="Output CSV file (default: exported_rules.csv)")
    parser.add_argument("--position", default="post", choices=["pre", "post"], help="Rule position (default: post)")
    parser.add_argument("--limit", type=int, default=500, help="Max number of rules to fetch (default: 500)")
    parser.add_argument("--json", action="store_true", help="Also print raw JSON to stdout")
    return parser.parse_args()


def main():
    args = parse_args()
    folder = os.getenv("SCM_FOLDER")

    print("Authenticating with SCM...")
    token = get_access_token()
    print("Authentication successful.\n")

    print(f"Fetching rules from folder '{folder}' (position: {args.position})...")
    rules = fetch_rules(token, folder, args.position, args.limit)
    print(f"Fetched {len(rules)} rules.\n")

    if args.json:
        print(json.dumps(rules, indent=2))

    fieldnames = [
        "rule_name", "description", "source_zone", "destination_zone",
        "source_address", "destination_address", "application", "service",
        "action", "log_start", "log_end", "profile_group", "tags"
    ]

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for rule in rules:
            writer.writerow(rule_to_csv_row(rule))

    print(f"Exported to: {args.output}")


if __name__ == "__main__":
    main()
