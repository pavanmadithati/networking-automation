#!/usr/bin/env python3
"""
Firewall Operations Utility
Provides:
  - HA health check for both firewalls in the pair
  - Post-deployment rule validation via SCM API + sync status
  - Unused security rules report (last 90 days) via PAN-OS XML API
"""

import os
import sys
import argparse
import logging
import requests
import urllib3
import xml.etree.ElementTree as ET
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

SCM_AUTH_URL = "https://auth.apps.paloaltonetworks.com/am/oauth2/access_token"
SCM_API_BASE = "https://api.sase.paloaltonetworks.com"


# ---------------------------------------------------------------------------
# PAN-OS XML API helpers (operational commands — allowed on SCM-managed FWs)
# ---------------------------------------------------------------------------

def get_panos_api_key(host: str, username: str, password: str) -> str:
    resp = requests.get(
        f"https://{host}/api",
        params={"type": "keygen", "user": username, "password": password},
        verify=False, timeout=15
    )
    resp.raise_for_status()
    root = ET.fromstring(resp.text)
    if root.attrib.get("status") != "success":
        raise RuntimeError(f"Auth failed on {host}: {resp.text}")
    return root.findtext("result/key")


def panos_op(host: str, api_key: str, cmd: str) -> ET.Element:
    resp = requests.get(
        f"https://{host}/api",
        params={"type": "op", "cmd": cmd, "key": api_key},
        verify=False, timeout=30
    )
    resp.raise_for_status()
    return ET.fromstring(resp.text)


# ---------------------------------------------------------------------------
# 1. HA Health Check
# ---------------------------------------------------------------------------

def check_ha_health():
    hosts = [
        os.getenv("PANOS_HOST_PRIMARY"),
        os.getenv("PANOS_HOST_SECONDARY"),
    ]
    username = os.getenv("PANOS_USERNAME")
    password = os.getenv("PANOS_PASSWORD")

    if not all([hosts[0], hosts[1], username, password]):
        log.error("Set PANOS_HOST_PRIMARY, PANOS_HOST_SECONDARY, PANOS_USERNAME, PANOS_PASSWORD in .env")
        sys.exit(1)

    print("\n" + "="*60)
    print("  HA HEALTH CHECK")
    print("="*60)

    all_healthy = True

    for host in hosts:
        print(f"\nFirewall: {host}")
        try:
            api_key = get_panos_api_key(host, username, password)

            # System info
            sys_root = panos_op(host, api_key, "<show><system><info></info></system></show>")
            model    = sys_root.findtext("result/system/model") or "N/A"
            sw_ver   = sys_root.findtext("result/system/sw-version") or "N/A"
            uptime   = sys_root.findtext("result/system/uptime") or "N/A"
            hostname = sys_root.findtext("result/system/hostname") or host

            print(f"  Hostname : {hostname}")
            print(f"  Model    : {model}")
            print(f"  SW Ver   : {sw_ver}")
            print(f"  Uptime   : {uptime}")

            # HA state
            ha_root  = panos_op(host, api_key, "<show><high-availability><state></state></high-availability></show>")
            ha_enabled = ha_root.findtext("result/enabled") or "no"

            if ha_enabled.lower() == "yes":
                ha_state    = ha_root.findtext("result/group/local-info/state") or "unknown"
                peer_state  = ha_root.findtext("result/group/peer-info/state") or "unknown"
                sync_state  = ha_root.findtext("result/group/running-sync") or "unknown"
                ha_mode     = ha_root.findtext("result/group/mode") or "unknown"

                print(f"  HA Mode  : {ha_mode}")
                print(f"  HA State : {ha_state.upper()}")
                print(f"  Peer     : {peer_state.upper()}")
                print(f"  Sync     : {sync_state}")

                if ha_state.lower() not in ("active", "passive"):
                    print(f"  [WARNING] Unexpected HA state: {ha_state}")
                    all_healthy = False
                if sync_state.lower() not in ("synchronized", "complete"):
                    print(f"  [WARNING] HA not fully synced: {sync_state}")
                    all_healthy = False
            else:
                print("  HA       : Not enabled")

        except Exception as e:
            print(f"  [ERROR] Could not reach {host}: {e}")
            all_healthy = False

    print("\n" + "="*60)
    if all_healthy:
        print("  RESULT: HA pair is HEALTHY — safe to proceed")
    else:
        print("  RESULT: WARNING — review issues above before pushing")
    print("="*60 + "\n")
    return all_healthy


# ---------------------------------------------------------------------------
# 2. Post-deployment Rule Validation
# ---------------------------------------------------------------------------

def get_scm_token() -> str:
    resp = requests.post(
        SCM_AUTH_URL,
        data={
            "grant_type": "client_credentials",
            "client_id": os.getenv("SCM_CLIENT_ID"),
            "client_secret": os.getenv("SCM_CLIENT_SECRET"),
            "scope": f"tsg_id:{os.getenv('SCM_TSG_ID')}"
        }
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def validate_rule_deployed(rule_names: list):
    folder   = os.getenv("SCM_FOLDER")
    position = os.getenv("SCM_POSITION", "pre")

    print("\n" + "="*60)
    print("  POST-DEPLOYMENT RULE VALIDATION")
    print("="*60)

    token = get_scm_token()
    headers = {"Authorization": f"Bearer {token}"}

    all_valid = True

    for rule_name in rule_names:
        print(f"\nValidating: {rule_name}")
        resp = requests.get(
            f"{SCM_API_BASE}/sse/config/v1/security-rules",
            headers=headers,
            params={"folder": folder, "position": position, "name": rule_name}
        )

        if resp.status_code == 404:
            print(f"  [FAIL] Rule NOT found in SCM")
            all_valid = False
            continue

        resp.raise_for_status()
        items = resp.json().get("data", [])
        rule  = next((r for r in items if r.get("name") == rule_name), None)

        if not rule:
            print(f"  [FAIL] Rule NOT found in SCM")
            all_valid = False
            continue

        print(f"  [OK]   Found in SCM (folder: {folder}, position: {position})")
        print(f"         Action      : {rule.get('action', 'N/A')}")
        print(f"         Application : {', '.join(rule.get('application', []))}")
        print(f"         Service     : {', '.join(rule.get('service', []))}")

    # Check firewall sync status
    print(f"\nChecking firewall sync status in SCM...")
    try:
        resp = requests.get(
            f"{SCM_API_BASE}/sse/config/v1/jobs",
            headers=headers,
            params={"folder": folder, "limit": 5}
        )
        if resp.ok:
            jobs = resp.json().get("data", [])
            for job in jobs:
                status     = job.get("status", "N/A")
                job_type   = job.get("type", "N/A")
                end_time   = job.get("end_time", "N/A")
                print(f"  Job [{job_type}] Status: {status} | Completed: {end_time}")
        else:
            print(f"  Could not retrieve job status: {resp.status_code}")
    except Exception as e:
        print(f"  Could not check sync status: {e}")

    print("\n" + "="*60)
    print(f"  RESULT: {'ALL RULES VALIDATED' if all_valid else 'SOME RULES MISSING — check above'}")
    print("="*60 + "\n")
    return all_valid


# ---------------------------------------------------------------------------
# 3. Unused Rules Report (last 90 days)
# ---------------------------------------------------------------------------

def unused_rules_report():
    host     = os.getenv("PANOS_HOST_PRIMARY")
    username = os.getenv("PANOS_USERNAME")
    password = os.getenv("PANOS_PASSWORD")
    vsys     = os.getenv("PANOS_VSYS", "vsys1")

    if not all([host, username, password]):
        log.error("Set PANOS_HOST_PRIMARY, PANOS_USERNAME, PANOS_PASSWORD in .env")
        sys.exit(1)

    print("\n" + "="*60)
    print("  UNUSED SECURITY RULES — LAST 90 DAYS")
    print(f"  Firewall : {host}  |  VSYS: {vsys}")
    print("="*60)

    api_key = get_panos_api_key(host, username, password)

    cmd = (
        f"<show><rule-use>"
        f"<rule-base>security</rule-base>"
        f"<vsys>{vsys}</vsys>"
        f"<type>unused</type>"
        f"<period>last-90-days</period>"
        f"</rule-use></show>"
    )

    root = panos_op(host, api_key, cmd)

    if root.attrib.get("status") != "success":
        print(f"  [ERROR] API returned: {ET.tostring(root, encoding='unicode')}")
        return

    entries = root.findall(".//entry")

    if not entries:
        print("\n  No unused rules found in the last 90 days.\n")
    else:
        print(f"\n  Found {len(entries)} unused rule(s):\n")
        print(f"  {'Rule Name':<50} {'Last Hit':<25}")
        print(f"  {'-'*50} {'-'*25}")
        for entry in entries:
            name     = entry.get("name", "N/A")
            last_hit = entry.findtext("last-hit-timestamp") or "Never"
            print(f"  {name:<50} {last_hit:<25}")

    print("\n" + "="*60 + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(description="Firewall Operations Utility")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("ha-check", help="Check HA health of firewall pair")

    val = sub.add_parser("validate", help="Validate rules are deployed in SCM")
    val.add_argument("rules", nargs="+", help="Rule name(s) to validate")

    sub.add_parser("unused-rules", help="Report unused rules in the last 90 days")

    sub.add_parser("all", help="Run ha-check, then validate, then unused-rules report")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.command == "ha-check":
        check_ha_health()

    elif args.command == "validate":
        validate_rule_deployed(args.rules)

    elif args.command == "unused-rules":
        unused_rules_report()

    elif args.command == "all":
        healthy = check_ha_health()
        if not healthy:
            print("Aborting — HA pair not healthy.")
            sys.exit(1)
        unused_rules_report()


if __name__ == "__main__":
    main()
