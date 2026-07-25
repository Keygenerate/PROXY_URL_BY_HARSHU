# CREATE BY HARSHU
"""
Free Fire Proxy Server — mitmproxy Addon v2.0
Features:
  • Landing page + health check
  • Proxy API endpoints (add-session, sessions, end-session)
  • JWT/AccessToken injection into MajorLogin requests
  • Active session validation on MajorLogin responses
"""

import os
import sys
import json
import base64
import traceback
from mitmproxy import http

# ─── CONFIG ───
ACTIVE_UIDS_FILE = "active_uids.json"
PROXY_HOST = os.getenv("PROXY_HOST", "proxy-url-by-harshu.onrender.com")

# ─── AES CRYPTO ───
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

CRYPTO_AVAILABLE = False
PROTOBUF_AVAILABLE = False
MajorLogin = None
MajorLoginRes = None
GameSecurity = None

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    CRYPTO_AVAILABLE = True
except ImportError as e:
    print(f"[CRYPTO] Import failed: {e}")

try:
    from google.protobuf import descriptor_pool as _descriptor_pool
    from google.protobuf.internal import builder as _builder
    PROTOBUF_AVAILABLE = True
except ImportError as e:
    print(f"[PROTOBUF] Import failed: {e}")

if PROTOBUF_AVAILABLE:
    try:
        REQ_DESCRIPTOR_B64 = "ChNNYWpvckxvZ2luUmVxLnByb3RvIvoKCgpNYWpvckxvZ2luEhIKCmV2ZW50X3RpbWUYAyABKAkSEQoJZ2FtZV9uYW1lGAQgASgJEhMKC3BsYXRmb3JtX2lkGAUgASgFEhYKDmNsaWVudF92ZXJzaW9uGAcgASgJEhcKD3N5c3RlbV9zb2Z0d2FyZRgIIAEoCRIXCg9zeXN0ZW1faGFyZHdhcmUYCSABKAkSGAoQdGVsZWNvbV9vcGVyYXRvchgKIAEoCRIUCgxuZXR3b3JrX3R5cGUYCyABKAkSFAoMc2NyZWVuX3dpZHRoGAwgASgNEhUKDXNjcmVlbl9oZWlnaHQYDSABKA0SEgoKc2NyZWVuX2RwaRgOIAEoCRIZChFwcm9jZXNzb3JfZGV0YWlscxgPIAEoCRIOCgZtZW1vcnkYECABKA0SFAoMZ3B1X3JlbmRlcmVyGBEgASgJEhMKC2dwdV92ZXJzaW9uGBIgASgJEhgKEHVuaXF1ZV9kZXZpY2VfaWQYEyABKAkSEQoJY2xpZW50X2lwGBQgASgJEhAKCGxhbmd1YWdlGBUgASgJEg8KB29wZW5faWQYFiABKAkSFAoMb3Blbl9pZF90eXBlGBcgASgJEhMKC2RldmljZV90eXBlGBggASgJEicKEG1lbW9yeV9hdmFpbGFibGUYGSABKAsyDS5HYW1lU2VjdXJpdHkSFAoMYWNjZXNzX3Rva2VuGB0gASgJEhcKD3BsYXRmb3JtX3Nka19pZBgeIAEoBRIaChJuZXR3b3JrX29wZXJhdG9yX2EYKSABKAkSFgoObmV0d29ya190eXBlX2EYKiABKAkSHAoUY2xpZW50X3VzaW5nX3ZlcnNpb24YOSABKAkSHgoWZXh0ZXJuYWxfc3RvcmFnZV90b3RhbBg8IAEoBRIiChpleHRlcm5hbF9zdG9yYWdlX2F2YWlsYWJsZRg9IAEoBRIeChZpbnRlcm5hbF9zdG9yYWdlX3RvdGFsGD4gASgFEiIKGmludGVybmFsX3N0b3JhZ2VfYXZhaWxhYmxlGD8gASgFEiMKG2dhbWVfZGlza19zdG9yYWdlX2F2YWlsYWJsZRhgIAEoBRIfChdnYW1lX2Rpc2tfc3RvcmFnZV90b3RhbBhBIAEoBRIlCh1leHRlcm5hbF9zZGNhcmRfYXZhaWxfc3RvcmFnZRhCIAEoBRIlCh1leHRlcm5hbF9zZGNhcmRfdG90YWxfc3RvcmFnZRhDIAEoBRIQCghsb2dpbl9ieRhJIAEoBRIUCgxsaWJyYXJ5X3BhdGgYSiABKAkSEgoKcmVnX2F2YXRhchhMIAEoBRIVCg1saWJyYXJ5X3Rva2VuGE0gASgJEhQKDGNoYW5uZWxfdHlwZRhOIAEoBRIQCghjcHVfdHlwZRgPIAEoBRIYChBjcHVfYXJjaGl0ZWN0dXJlGFEgASgJEhsKE2NsaWVudF92ZXJzaW9uX2NvZGUYUyABKAkSFAoMZ3JhcGhpY3NfYXBpGFYgASgJEh0KFXN1cHBvcnRlZF9hc3RjX2JpdHNldBhXIAEoDRIaChJsb2dpbl9vcGVuX2lkX3R5cGUYWCABKAUSGAoQYW5hbHl0aWNzX2RldGFpbBhZIAEoDBIUCgxsb2FkaW5nX3RpbWUYXCABKA0SFwoPcmVsZWFzZV9jaGFubmVsGF0gASgJEhIKCmV4dHJhX2luZm8YXiABKAkSIAoYYW5kcm9pZF9lbmdpbmVfaW5pdF9mbGFnGF8gASgNEg8KB2lmX3B1c2gYYSABKAUSDgoGaXNfdnBuGGIgASgFEhwKFG9yaWdpbl9wbGF0Zm9ybV90eXBlGGMgASgJEh0KFXByaW1hcnlfcGxhdGZvcm1fdHlwZRhkIAEoCSI1CgxHYW1lU2VjdXJpdHkSDwoHdmVyc2lvbhgGIAEoBRIUCgxoaWRkZW5fdmFsdWUYCCABKARiBnByb3RvMw=="
        RES_DESCRIPTOR_B64 = "ChNNYWpvckxvZ2luUmVzLnByb3RvInwKDU1ham9yTG9naW5SZXMSEwoLYWNjb3VudF91aWQYASABKAQSDgoGcmVnaW9uGAIgASgJEg0KBXRva2VuGAggASgJEgsKA3VybBgKIAEoCRIRCgl0aW1lc3RhbXAYFSABKAMSCwoDa2V5GBYgASgMEgoKAml2GBcgASgMYgZwcm90bzM="

        req_bytes = base64.b64decode(REQ_DESCRIPTOR_B64)
        res_bytes = base64.b64decode(RES_DESCRIPTOR_B64)

        pool = _descriptor_pool.Default()
        d1 = pool.AddSerializedFile(req_bytes)
        d2 = pool.AddSerializedFile(res_bytes)

        _globals = globals()
        _builder.BuildMessageAndEnumDescriptors(d1, _globals)
        _builder.BuildTopDescriptorsAndMessages(d1, 'MajorLoginReq_pb2', _globals)
        MajorLogin = _globals['MajorLogin']
        GameSecurity = _globals['GameSecurity']

        _globals2 = globals()
        _builder.BuildMessageAndEnumDescriptors(d2, _globals2)
        _builder.BuildTopDescriptorsAndMessages(d2, 'MajorLoginRes_pb2', _globals2)
        MajorLoginRes = _globals2['MajorLoginRes']

        print("[PROTOBUF] Classes loaded successfully")
    except Exception as e:
        print(f"[PROTOBUF] Load failed: {e}")
        MajorLogin = None
        MajorLoginRes = None
        GameSecurity = None

# ─── HELPERS ───
def load_active_uids():
    try:
        if os.path.exists(ACTIVE_UIDS_FILE):
            with open(ACTIVE_UIDS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        print(f"[ACTIVE] Error loading: {e}")
    return {}

def save_active_uids(data):
    try:
        with open(ACTIVE_UIDS_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"[ACTIVE] Error saving: {e}")
        return False

def extract_uid_from_login_response(data: bytes) -> str:
    """Extract UID from MajorLogin response protobuf (varint after 0x08)."""
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

def make_json_response(data, status=200):
    body = json.dumps(data).encode('utf-8')
    return http.Response.make(
        status, body,
        {"Content-Type": "application/json", "Content-Length": str(len(body))}
    )

# ─── MAIN ADDON CLASS ───
class FreeFireProxy:
    def __init__(self):
        print(f"[PROXY] Initialized | Host: {PROXY_HOST}")
        print(f"[PROXY] Crypto: {CRYPTO_AVAILABLE} | Protobuf: {PROTOBUF_AVAILABLE} | MajorLogin: {MajorLogin is not None}")

    # ─── Check if request is for proxy's own API ───
    def _is_proxy_api(self, flow: http.HTTPFlow) -> bool:
        host = (flow.request.host or "").lower()
        return (PROXY_HOST.lower() in host) and flow.request.path.startswith("/api/proxy/")

    # ─── REQUEST HANDLER ───
    def request(self, flow: http.HTTPFlow) -> None:
        path = flow.request.path
        method = flow.request.method.upper()

        # 1) Proxy API endpoints
        if self._is_proxy_api(flow):
            self._handle_proxy_api(flow)
            return

        # 2) Landing page for root
        if path == "/" and method == "GET":
            self._serve_landing(flow)
            return

        # 3) JWT Injection for MajorLogin requests
        if method == "POST" and "majorlogin" in path.lower():
            self._inject_jwt(flow)

    # ─── RESPONSE HANDLER ───
    def response(self, flow: http.HTTPFlow) -> None:
        if flow.request.method.upper() == "POST" and "majorlogin" in flow.request.path.lower():
            resp_bytes = flow.response.content
            uid_str = extract_uid_from_login_response(resp_bytes)

            if uid_str:
                active_uids = load_active_uids()
                if uid_str in active_uids:
                    print(f"[ALLOW] UID {uid_str} is ACTIVE")
                else:
                    print(f"[BLOCK] UID {uid_str} NOT ACTIVE — Session ENDED")
                    new_response = bytes.fromhex("6a0a0891a40118f697fcc4067a020801")
                    flow.response.content = new_response
                    flow.response.status_code = 200
                    flow.response.headers["Content-Type"] = "application/octet-stream"
                    flow.response.headers["Content-Length"] = str(len(new_response))

    # ─── LANDING PAGE ───
    def _serve_landing(self, flow: http.HTTPFlow):
        sessions = load_active_uids()
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HARSHU FF Proxy</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ background:#0f0f0f; color:#fff; font-family:'Segoe UI',sans-serif; display:flex; justify-content:center; align-items:center; min-height:100vh; }}
        .card {{ background:#1a1a1a; border:1px solid #333; border-radius:16px; padding:40px; max-width:420px; width:90%; text-align:center; box-shadow:0 0 40px rgba(255,100,0,0.1); }}
        .status {{ display:flex; align-items:center; justify-content:center; gap:8px; margin-bottom:20px; }}
        .dot {{ width:12px; height:12px; background:#00ff88; border-radius:50%; box-shadow:0 0 10px #00ff88; animation:pulse 2s infinite; }}
        @keyframes pulse {{ 0%,100%{{opacity:1}} 50%{{opacity:0.5}} }}
        h1 {{ font-size:24px; margin-bottom:8px; background:linear-gradient(90deg,#ff6b00,#ffcc00); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }}
        .info {{ color:#888; font-size:14px; margin-bottom:24px; }}
        .stats {{ display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:20px; }}
        .stat {{ background:#222; padding:12px; border-radius:8px; }}
        .stat-value {{ font-size:20px; font-weight:bold; color:#ff6b00; }}
        .stat-label {{ font-size:12px; color:#666; margin-top:4px; }}
        .brand {{ margin-top:20px; padding-top:20px; border-top:1px solid #333; font-size:14px; color:#555; }}
        .brand b {{ color:#ff6b00; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="status"><div class="dot"></div><span>Server Active</span></div>
        <h1>HARSHU FF Proxy</h1>
        <div class="info">v2.0 | JWT Injection + Session Control</div>
        <div class="stats">
            <div class="stat"><div class="stat-value">{len(sessions)}</div><div class="stat-label">Active Sessions</div></div>
            <div class="stat"><div class="stat-value">{'ON' if CRYPTO_AVAILABLE else 'OFF'}</div><div class="stat-label">Crypto</div></div>
            <div class="stat"><div class="stat-value">{'ON' if PROTOBUF_AVAILABLE else 'OFF'}</div><div class="stat-label">Protobuf</div></div>
            <div class="stat"><div class="stat-value">{'ON' if MajorLogin else 'OFF'}</div><div class="stat-label">JWT Inject</div></div>
        </div>
        <div class="brand">👨‍💻 <b>CREATE BY HARSHU</b></div>
    </div>
</body>
</html>"""
        flow.response = http.Response.make(
            200, html.encode('utf-8'),
            {"Content-Type": "text/html; charset=utf-8"}
        )

    # ─── PROXY API HANDLER ───
    def _handle_proxy_api(self, flow: http.HTTPFlow):
        path = flow.request.path
        method = flow.request.method.upper()

        # GET /api/proxy/health
        if path == "/api/proxy/health" and method == "GET":
            flow.response = make_json_response({
                "success": True,
                "status": "ok",
                "version": "2.0",
                "crypto": CRYPTO_AVAILABLE,
                "protobuf": PROTOBUF_AVAILABLE,
                "jwt_inject": MajorLogin is not None,
                "active_sessions": len(load_active_uids())
            })
            return

        # GET /api/proxy/sessions
        if path == "/api/proxy/sessions" and method == "GET":
            sessions = load_active_uids()
            flow.response = make_json_response({
                "success": True,
                "count": len(sessions),
                "sessions": list(sessions.values())
            })
            return

        # POST /api/proxy/add-session
        if path == "/api/proxy/add-session" and method == "POST":
            try:
                body = json.loads(flow.request.content or b"{}")
                uid = str(body.get("uid", ""))
                open_id = str(body.get("open_id", ""))
                access_token = str(body.get("access_token", ""))
                jwt = str(body.get("jwt", ""))

                if not uid or not open_id:
                    flow.response = make_json_response({"success": False, "error": "uid and open_id required"}, 400)
                    return

                active = load_active_uids()
                active[uid] = {
                    "uid": uid,
                    "open_id": open_id,
                    "access_token": access_token,
                    "jwt": jwt[:50] + "..." if len(jwt) > 50 else jwt,
                    "created_at": __import__('datetime').datetime.now().isoformat(),
                    "status": "active"
                }
                save_active_uids(active)
                print(f"[API] Session added: UID={uid}, open_id={open_id}")
                flow.response = make_json_response({"success": True, "message": "Session added", "uid": uid})
            except Exception as e:
                flow.response = make_json_response({"success": False, "error": str(e)}, 500)
            return

        # GET/POST /api/proxy/session/{uid}/end
        if path.startswith("/api/proxy/session/") and path.endswith("/end"):
            try:
                uid = path.split("/")[4]
                active = load_active_uids()
                if uid in active:
                    del active[uid]
                    save_active_uids(active)
                    flow.response = make_json_response({"success": True, "message": f"Session ended for UID {uid}"})
                else:
                    flow.response = make_json_response({"success": False, "error": "UID not found"}, 404)
            except Exception as e:
                flow.response = make_json_response({"success": False, "error": str(e)}, 500)
            return

        # GET /api/proxy/session/{uid}/status
        if path.startswith("/api/proxy/session/") and path.endswith("/status"):
            try:
                uid = path.split("/")[4]
                active = load_active_uids()
                is_active = uid in active
                flow.response = make_json_response({
                    "success": True, "uid": uid, "active": is_active,
                    "status": "active" if is_active else "ended"
                })
            except Exception as e:
                flow.response = make_json_response({"success": False, "error": str(e)}, 500)
            return

        # Fallback
        flow.response = make_json_response({"success": False, "error": "Unknown endpoint"}, 404)

    # ─── JWT INJECTION ───
    def _inject_jwt(self, flow: http.HTTPFlow):
        if not CRYPTO_AVAILABLE or not PROTOBUF_AVAILABLE or MajorLogin is None:
            print(f"[INJECT] Skipped — crypto={CRYPTO_AVAILABLE}, protobuf={PROTOBUF_AVAILABLE}, MajorLogin={MajorLogin is not None}")
            return

        try:
            encrypted_body = flow.request.content
            if not encrypted_body or len(encrypted_body) < 16:
                return

            # Decrypt
            cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
            decrypted = unpad(cipher.decrypt(encrypted_body), AES.block_size)

            # Parse protobuf
            major = MajorLogin()
            major.ParseFromString(decrypted)

            open_id = major.open_id
            if not open_id:
                print("[INJECT] No open_id found in request")
                return

            # Find session by open_id
            active_uids = load_active_uids()
            session = None
            for uid, data in active_uids.items():
                if data.get("open_id") == open_id:
                    session = data
                    break

            if session and session.get("access_token"):
                old_token = major.access_token
                major.access_token = session["access_token"]

                # Re-serialize & re-encrypt
                new_body = major.SerializeToString()
                cipher2 = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
                new_encrypted = cipher2.encrypt(pad(new_body, AES.block_size))

                flow.request.content = new_encrypted
                flow.request.headers["Content-Length"] = str(len(new_encrypted))
                print(f"[INJECT] ✅ AccessToken replaced for open_id={open_id} | Old: {old_token[:20]}... | New: {session['access_token'][:20]}...")
            else:
                print(f"[INJECT] ⚠️ No active session for open_id={open_id}")

        except Exception as e:
            print(f"[INJECT] ❌ Error: {e}")
            traceback.print_exc()

addons = [FreeFireProxy()]
