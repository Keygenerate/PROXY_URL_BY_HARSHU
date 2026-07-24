# CREATE BY HARSHU
"""
Mitmproxy Addon with Active Session Check
Only allows UIDs that are in active_uids.json
"""

import os
import json
from mitmproxy import http

ACTIVE_UIDS_FILE = "active_uids.json"

def load_active_uids():
    try:
        if os.path.exists(ACTIVE_UIDS_FILE):
            with open(ACTIVE_UIDS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        print(f"[ACTIVE_CHECK] Error: {e}")
    return {}

def extract_uid_from_login_response(data: bytes) -> str:
    try:
        if len(data) < 2:
            return None
        if data[0] == 0x08:
            uid = 0
            shift = 0
            pos = 1
            while pos < len(data):
                byte = data[pos]
                uid |= (byte & 0x7F) << shift
                shift += 7
                pos += 1
                if not (byte & 0x80):
                    break
            return str(uid)
        for i in range(len(data) - 1):
            if data[i] == 0x08:
                uid = 0
                shift = 0
                pos = i + 1
                while pos < len(data):
                    byte = data[pos]
                    uid |= (byte & 0x7F) << shift
                    shift += 7
                    pos += 1
                    if not (byte & 0x80):
                        break
                return str(uid)
        return None
    except Exception as e:
        print(f"[UID] Error: {e}")
        return None

class SessionChecker:
    def response(self, flow: http.HTTPFlow) -> None:
        if flow.request.method.upper() == "POST" and "majorlogin" in flow.request.path.lower():
            resp_bytes = flow.response.content
            uid_str = extract_uid_from_login_response(resp_bytes)

            if uid_str:
                active_uids = load_active_uids()

                if uid_str in active_uids:
                    print(f"[ALLOW] UID {uid_str} is ACTIVE")
                else:
                    print(f"[BLOCK] UID {uid_str} NOT ACTIVE - Session ENDED")
                    new_response = bytes.fromhex("6a0a0891a40118f697fcc4067a020801")
                    flow.response.content = new_response
                    flow.response.status_code = 200
                    flow.response.headers["Content-Type"] = "application/octet-stream"
                    flow.response.headers["Content-Length"] = str(len(new_response))

addons = [SessionChecker()]
