#!/usr/bin/env python3
"""
PAN-OS Firewall Rule Importer
Reads security policy rules from a CSV file and pushes them to a
Palo Alto Networks firewall or Panorama via the XML API.

Requirements:
    pip install pan-os-python requests urllib3
"""

import csv
import sys
import argparse
import logging
import urllib3
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

import requests
from dotenv import load_dotenv
import os

load_dotenv()

# Suppress SSL warnings for self-signed certs (common in firewall environments)
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
        """Raise ValueError if required fields are missing or invalid."""
        if not self.rule_name:
            raise ValueError("rule_name is required")
        if self.action not in ("allow", "deny", "drop", "reset-client", "reset-server", "reset-both"):
            raise ValueError(f"Invalid action '{self.action}' in rule '{self.rule_name}'")
        if not self.source_zone or not self.destination_zone:
            raise ValueError(f"Zones are required in rule '{self.rule_name}'")


# ---------------------------------------------------------------------------
# XML builder
# ---------------------------------------------------------------------------

def _member_elements(values: str) -> list[ET.Element]:
    """Convert a semicolon-separated string into a list of <member> elements."""
    elements = []
    for val in values.split(";"):
        val = val.strip()
        if val:
            m = ET.Element("member")
            m.text = val
            elements.append(m)
    return elements


def rule_to_xml(rule: FirewallRule) -> ET.Element:
    """Build the PAN-OS XML element for a single security rule."""
    entry = ET.Element("entry", name=rule.rule_name)

    # Description
    if rule.description:
        desc = ET.SubElement(entry, "description")
        desc.text = rule.description

    # Source zone
    from_el = ET.SubElement(entry, "from")
    for m in _member_elements(rule.source_zone):
        from_el.append(m)

    # Destination zone
    to_el = ET.SubElement(entry, "to")
    for m in _member_elements(rule.destination_zone):
        to_el.append(m)

    # Source address
    src = ET.SubElement(entry, "source")
    for m in _member_elements(rule.source_address):
        src.append(m)

    # Destination address
    dst = ET.SubElement(entry, "destination")
    for m in _member_elements(rule.destination_address):
        dst.append(m)

    # Application
    app = ET.SubElement(entry, "application")
    for m in _member_elements(rule.application):
        app.append(m)

    # Service
    svc = ET.SubElement(entry, "service")
    for m in _member_elements(rule.service):
        svc.append(m)

    # Action
    action_el = ET.SubElement(entry, "action")
    action_el.text = rule.action

    # Logging
    log_setting = ET.SubElement(entry, "log-setting")
    log_setting.text = "default"
    ET.SubElement(entry, "log-start").text = rule.log_start
    ET.SubElement(entry, "log-end").text = rule.log_end

    # Security profile group (optional)
    if rule.profile_group:
        pg = ET.SubElement(entry, "profile-setting")
        group = ET.SubElement(pg, "group")
        m = ET.SubElement(group, "member")
        m.text = rule.profile_group

    # Tags (optional)
    if rule.tags:
        tag_el = ET.SubElement(entry, "tag")
        for m in _member_elements(rule.tags):
            tag_el.append(m)

    return entry


# ---------------------------------------------------------------------------
# PAN-OS API client
# ---------------------------------------------------------------------------

class PanOSClient:
    def __init__(self, host: str, api_key: str, verify_ssl: bool = False):
        self.base_url = f"https://{host}/api"
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl

    @classmethod
    def get_api_key(cls, host: str, username: str, password: str, verify_ssl: bool = False) -> str:
        """Retrieve an API key using credentials."""
        url = f"https://{host}/api"
        resp = requests.get(
            url,
            params={"type": "keygen", "user": username, "password": password},
            verify=verify_ssl,
            timeout=15,
        )
        resp.raise_for_status()
        root = ET.fromstring(resp.text)
        if root.attrib.get("status") != "success":
            raise RuntimeError(f"Authentication failed: {resp.text}")
        return root.findtext("result/key")

    def _post(self, params: dict) -> ET.Element:
        params["key"] = self.api_key
        resp = self.session.post(self.base_url, data=params, timeout=30)
        resp.raise_for_status()
        root = ET.fromstring(resp.text)
        if root.attrib.get("status") != "success":
            raise RuntimeError(f"API error: {resp.text}")
        return root

    def rule_exists(self, xpath: str) -> bool:
        try:
            self._post({"type": "config", "action": "get", "xpath": xpath})
            return True
        except RuntimeError:
            return False

    def push_rule(self, rule: FirewallRule, vsys: str = "vsys1", overwrite: bool = False):
        xpath = (
            f"/config/devices/entry[@name='localhost.localdomain']"
            f"/vsys/entry[@name='{vsys}']"
            f"/rulebase/security/rules/entry[@name='{rule.rule_name}']"
        )
        xml_element = rule_to_xml(rule)
        xml_str = ET.tostring(xml_element, encoding="unicode")

        if self.rule_exists(xpath):
            if overwrite:
                log.info("Overwriting existing rule: %s", rule.rule_name)
                self._post({"type": "config", "action": "edit", "xpath": xpath, "element": xml_str})
            else:
                log.warning("Rule already exists, skipping (use --overwrite): %s", rule.rule_name)
                return False
        else:
            self._post({"type": "config", "action": "set", "xpath": xpath, "element": xml_str})

        log.info("Rule pushed successfully: %s", rule.rule_name)
        return True

    def commit(self, description: str = "Imported via CSV importer"):
        log.info("Committing configuration...")
        self._post({"type": "commit", "cmd": f"<commit><description>{description}</description></commit>"})
        log.info("Commit successful.")


# ---------------------------------------------------------------------------
# CSV reader
# ---------------------------------------------------------------------------

REQUIRED_COLUMNS = {
    "rule_name", "source_zone", "destination_zone",
    "source_address", "destination_address",
    "application", "service", "action",
}

def load_rules_from_csv(csv_path: str) -> list[FirewallRule]:
    rules = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV is missing required columns: {missing}")

        for i, row in enumerate(reader, start=2):  # row 1 is header
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
# Dry-run: print generated XML without connecting to firewall
# ---------------------------------------------------------------------------

def dry_run(rules: list[FirewallRule]):
    print("\n=== DRY RUN — Generated XML ===\n")
    for rule in rules:
        xml_el = rule_to_xml(rule)
        ET.indent(xml_el, space="  ")
        print(ET.tostring(xml_el, encoding="unicode"))
        print()
    print(f"Total rules: {len(rules)}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Import PAN-OS security rules from a CSV file"
    )
    parser.add_argument("csv_file", help="Path to the CSV file containing firewall rules")
    parser.add_argument("--host", default=os.getenv("PANOS_HOST"), help="Firewall/Panorama hostname or IP")
    parser.add_argument("--username", default=os.getenv("PANOS_USERNAME"), help="Admin username")
    parser.add_argument("--password", default=os.getenv("PANOS_PASSWORD"), help="Admin password")
    parser.add_argument("--api-key", default=os.getenv("PANOS_API_KEY") or None, help="API key (alternative to username/password)")
    parser.add_argument("--vsys", default=os.getenv("PANOS_VSYS", "vsys1"), help="Target vsys (default: vsys1)")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing rules")
    parser.add_argument("--commit", action="store_true", help="Commit after pushing rules")
    parser.add_argument("--dry-run", action="store_true",
                        help="Parse CSV and print XML without connecting to firewall")
    parser.add_argument("--verify-ssl", action="store_true",
                        help="Verify SSL certificate (default: off for self-signed certs)")
    return parser.parse_args()


def main():
    args = parse_args()

    log.info("Loading rules from: %s", args.csv_file)
    rules = load_rules_from_csv(args.csv_file)
    log.info("Loaded %d valid rules", len(rules))

    if args.dry_run:
        dry_run(rules)
        return

    if not args.host:
        log.error("--host is required unless using --dry-run")
        sys.exit(1)

    # Resolve API key
    if args.api_key:
        api_key = args.api_key
    elif args.username and args.password:
        log.info("Retrieving API key for %s@%s", args.username, args.host)
        api_key = PanOSClient.get_api_key(
            args.host, args.username, args.password, verify_ssl=args.verify_ssl
        )
    else:
        log.error("Provide --api-key or both --username and --password")
        sys.exit(1)

    client = PanOSClient(args.host, api_key, verify_ssl=args.verify_ssl)

    pushed = 0
    for rule in rules:
        if client.push_rule(rule, vsys=args.vsys, overwrite=args.overwrite):
            pushed += 1

    log.info("Pushed %d/%d rules", pushed, len(rules))

    if args.commit and pushed > 0:
        client.commit()


if __name__ == "__main__":
    main()
