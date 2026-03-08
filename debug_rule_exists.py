#!/usr/bin/env python3
"""Debug script to check what the PAN-OS API returns for a specific rule lookup."""

import os
import xml.etree.ElementTree as ET
from dotenv import load_dotenv
from import_firewall_rules import PanOSClient

load_dotenv()

client = PanOSClient(os.getenv("PANOS_HOST"), os.getenv("PANOS_API_KEY"))

rule_name = "allow-rdp-admin-testpavan-test"
vsys = os.getenv("PANOS_VSYS", "vsys1")

xpath = (
    f"/config/devices/entry[@name='localhost.localdomain']"
    f"/vsys/entry[@name='{vsys}']"
    f"/rulebase/security/rules/entry[@name='{rule_name}']"
)

print(f"Checking xpath: {xpath}\n")

try:
    result = client._post({"type": "config", "action": "get", "xpath": xpath})
    ET.indent(result, space="  ")
    print("API returned SUCCESS:")
    print(ET.tostring(result, encoding="unicode"))
except RuntimeError as e:
    print(f"API returned ERROR: {e}")
