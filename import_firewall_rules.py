#!/usr/bin/env python3
"""
Strata Cloud Manager (SCM) Firewall Rule Importer
Reads security policy rules from a CSV file and pushes them to
Palo Alto Strata Cloud Manager via the REST API.

Requirements:
    pip install requests urllib3 python-dotenv
"""

import csv
import sys
import argparse
import logging
import urllib3
import os
from dataclasses import dataclass
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class FirewallRule:
    rule_name: str
    source_zone: str
    destination_zone: str
    source_address: str
    destination_address: str
    application: str
    service: str
    action: str
    description: str = ""
    log_start: str = "no"
    log_end: str = "yes"
    profile_group: str = ""
    tags: str = ""

    def validate(self):
        if not self.rule_name:
            raise ValueError("rule_name is required")
        if self.action not in ("allow", "deny", "drop", "reset-client", "reset-server", "reset-both"):
            raise ValueError(f"Invalid action '{self.action}' in rule '{self.rule_name}'")
        if not self.source_zone or not self.destination_zone:
            raise ValueError(f"Zones are required in rule '{self.rule_name}'")


# ---------------------------------------------------------------------------
# SCM API client
# ---------------------------------------------------------------------------

SCM_AUTH_URL = "https://auth.apps.paloaltonetworks.com/am/oauth2/access_token"
SCM_API_BASE = "https://api.sase.paloaltonetworks.com"


class SCMClient:
    def __init__(self, client_id: str, client_secret: str, tsg_id: str, folder: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.tsg_id = tsg_id
        self.folder = folder
        self.session = requests.Session()
        self.access_token = self._get_access_token()
        self.session.headers.update({
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        })

    def _get_access_token(self) -> str:
        log.info("Authenticating with SCM...")
        resp = requests.post(
            SCM_AUTH_URL,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": f"tsg_id:{self.tsg_id}"
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        resp.raise_for_status()
        token = resp.json().get("access_token")
        if not token:
            raise RuntimeError("Failed to retrieve access token from SCM")
        log.info("Authentication successful.")
        return token

    def _url(self, path: str) -> str:
        return f"{SCM_API_BASE}{path}"

    def get_rule(self, rule_name: str) -> Optional[dict]:
        resp = self.session.get(
            self._url("/sse/config/v1/security-rules"),
            params={"folder": self.folder, "name": rule_name}
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
        items = data.get("data", [])
        for item in items:
            if item.get("name") == rule_name:
                return item
        return None

    def _rule_to_payload(self, rule: FirewallRule) -> dict:
        payload = {
            "name": rule.rule_name,
            "folder": self.folder,
            "from": [z.strip() for z in rule.source_zone.split(";") if z.strip()],
            "to": [z.strip() for z in rule.destination_zone.split(";") if z.strip()],
            "source": [a.strip() for a in rule.source_address.split(";") if a.strip()],
            "destination": [a.strip() for a in rule.destination_address.split(";") if a.strip()],
            "source_user": ["any"],
            "category": ["any"],
            "application": [a.strip() for a in rule.application.split(";") if a.strip()],
            "service": [s.strip() for s in rule.service.split(";") if s.strip()],
            "action": rule.action,
            "log_start": rule.log_start == "yes",
            "log_end": rule.log_end == "yes",
        }
        if rule.description:
            payload["description"] = rule.description
        if rule.profile_group:
            payload["profile_setting"] = {"group": [rule.profile_group]}
        if rule.tags:
            payload["tag"] = [t.strip() for t in rule.tags.split(";") if t.strip()]
        return payload

    def push_rule(self, rule: FirewallRule, overwrite: bool = False) -> bool:
        existing = self.get_rule(rule.rule_name)
        payload = self._rule_to_payload(rule)

        if existing:
            if overwrite:
                rule_id = existing["id"]
                log.info("Overwriting existing rule: %s", rule.rule_name)
                resp = self.session.put(
                    self._url(f"/sse/config/v1/security-rules/{rule_id}"),
                    params={"folder": self.folder},
                    json=payload
                )
                resp.raise_for_status()
            else:
                log.warning("Rule already exists, skipping (use --overwrite): %s", rule.rule_name)
                return False
        else:
            resp = self.session.post(
                self._url("/sse/config/v1/security-rules"),
                params={"folder": self.folder, "position": "post"},
                json=payload
            )
            if not resp.ok:
                log.error("SCM API error %s: %s", resp.status_code, resp.text)
            resp.raise_for_status()

        log.info("Rule pushed successfully: %s", rule.rule_name)
        return True

    def commit(self, description: str = "Imported via CSV importer"):
        log.info("Committing configuration to SCM...")
        resp = self.session.post(
            self._url("/sse/config/v1/config-versions/candidate:push"),
            json={"folders": [self.folder], "description": description}
        )
        resp.raise_for_status()
        log.info("Commit pushed successfully.")


# ---------------------------------------------------------------------------
# CSV reader
# ---------------------------------------------------------------------------

REQUIRED_COLUMNS = {
    "rule_name", "source_zone", "destination_zone",
    "source_address", "destination_address",
    "application", "service", "action",
}


def load_rules_from_csv(csv_path: str) -> list:
    rules = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV is missing required columns: {missing}")
        for i, row in enumerate(reader, start=2):
            try:
                rule = FirewallRule(
                    rule_name=row["rule_name"].strip(),
                    description=row.get("description", "").strip(),
                    source_zone=row["source_zone"].strip(),
                    destination_zone=row["destination_zone"].strip(),
                    source_address=row["source_address"].strip(),
                    destination_address=row["destination_address"].strip(),
                    application=row["application"].strip(),
                    service=row["service"].strip(),
                    action=row["action"].strip().lower(),
                    log_start=row.get("log_start", "no").strip().lower(),
                    log_end=row.get("log_end", "yes").strip().lower(),
                    profile_group=row.get("profile_group", "").strip(),
                    tags=row.get("tags", "").strip(),
                )
                rule.validate()
                rules.append(rule)
            except (ValueError, KeyError) as e:
                log.error("Skipping row %d due to error: %s", i, e)
    return rules


# ---------------------------------------------------------------------------
# Dry-run
# ---------------------------------------------------------------------------

def dry_run(rules: list):
    print("\n=== DRY RUN — Rules to be pushed ===\n")
    for rule in rules:
        print(f"Rule: {rule.rule_name}")
        print(f"  Action      : {rule.action}")
        print(f"  Source Zone : {rule.source_zone}")
        print(f"  Dest Zone   : {rule.destination_zone}")
        print(f"  Source Addr : {rule.source_address}")
        print(f"  Dest Addr   : {rule.destination_address}")
        print(f"  Application : {rule.application}")
        print(f"  Service     : {rule.service}")
        if rule.description:
            print(f"  Description : {rule.description}")
        if rule.profile_group:
            print(f"  Profile Grp : {rule.profile_group}")
        if rule.tags:
            print(f"  Tags        : {rule.tags}")
        print()
    print(f"Total rules: {len(rules)}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Import security rules from a CSV file into Strata Cloud Manager"
    )
    parser.add_argument("csv_file", help="Path to the CSV file containing firewall rules")
    parser.add_argument("--client-id", default=os.getenv("SCM_CLIENT_ID"), help="SCM OAuth2 client ID")
    parser.add_argument("--client-secret", default=os.getenv("SCM_CLIENT_SECRET"), help="SCM OAuth2 client secret")
    parser.add_argument("--tsg-id", default=os.getenv("SCM_TSG_ID"), help="SCM Tenant Service Group ID")
    parser.add_argument("--folder", default=os.getenv("SCM_FOLDER", "Shared"), help="SCM folder (default: Shared)")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing rules")
    parser.add_argument("--commit", action="store_true", help="Push candidate config after importing rules")
    parser.add_argument("--dry-run", action="store_true", help="Parse CSV and print rules without connecting to SCM")
    return parser.parse_args()


def main():
    args = parse_args()

    log.info("Loading rules from: %s", args.csv_file)
    rules = load_rules_from_csv(args.csv_file)
    log.info("Loaded %d valid rules", len(rules))

    if args.dry_run:
        dry_run(rules)
        return

    if not all([args.client_id, args.client_secret, args.tsg_id]):
        log.error("SCM_CLIENT_ID, SCM_CLIENT_SECRET, and SCM_TSG_ID are required")
        sys.exit(1)

    client = SCMClient(args.client_id, args.client_secret, args.tsg_id, args.folder)

    pushed = 0
    for rule in rules:
        try:
            if client.push_rule(rule, overwrite=args.overwrite):
                pushed += 1
        except Exception as e:
            log.error("Failed to push rule %s: %s", rule.rule_name, e)

    log.info("Pushed %d/%d rules", pushed, len(rules))

    if args.commit and pushed > 0:
        client.commit()


if __name__ == "__main__":
    main()
