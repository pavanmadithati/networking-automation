#!/usr/bin/env python3
"""Fetch and print the JSON structure of existing SCM security rules."""

import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

# Authenticate
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
token = resp.json()["access_token"]
print("Authentication successful.\n")

# Fetch rules
resp = requests.get(
    "https://api.sase.paloaltonetworks.com/sse/config/v1/security-rules",
    headers={"Authorization": f"Bearer {token}"},
    params={
        "folder": os.getenv("SCM_FOLDER"),
        "position": "post",
        "limit": 1
    }
)
resp.raise_for_status()
print(json.dumps(resp.json(), indent=2))
