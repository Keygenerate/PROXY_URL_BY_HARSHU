# CREATE BY HARSHU
"""
Free Fire Proxy Server - mitmproxy Addon
Landing page + Active Session Check
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

class FreeFireProxy:
    def request(self, flow: http.HTTPFlow) -> None:
        path = flow.request.path

        is_landing = False
        if path == "/":
            is_landing = True
        else:
            parts = [p for p in path.split("/") if p]
            if parts and parts[0].isdigit():
                is_landing = True

        if is_landing and flow.request.method == "GET":
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxy Server - HARSHU</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: #ffffff;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: flex-start;
            align-items: flex-start;
            min-height: 100vh;
            padding: 20px;
        }}
        .status-box {{
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}
        .status-line {{
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 14px;
            color: #333;
        }}
        .check {{
            color: #28a745;
            font-size: 16px;
        }}
        .uri-text {{
            color: #555;
            font-size: 13px;
            margin-left: 22px;
        }}
        .brand {{
            margin-top: 8px;
            font-size: 14px;
            color: #333;
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .brand-icon {{
            font-size: 16px;
        }}
    </style>
</head>
<body>
    <div class="status-box">
        <div class="status-line">
            <span class="check">✅</span>
            <span><b>Server Active</b></span>
        </div>
        <div class="uri-text">Server URI: {flow.request.url}</div>
        <div class="brand">
            <span class="brand-icon">👨‍💻</span>
            <span><b>CREATE BY HARSHU</b></span>
        </div>
    </div>
</body>
</html>"""
            flow.response = http.Response.make(
                200,
                html_content.encode('utf-8'),
                {"Content-Type": "text/html; charset=utf-8"}
            )
            return

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

addons = [FreeFireProxy()]
