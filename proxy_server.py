# CREATE BY HARSHU
"""
Free Fire Proxy Server for Render
Starts mitmdump with app.py addon
"""

import os
import sys

port = int(os.getenv("PORT", 10000))

print(f"""
╔══════════════════════════════════════════════════════════╗
║           FREE FIRE PROXY SERVER v2.0                    ║
║                                                          ║
║  CREATE BY HARSHU                                        ║
║  Running on port: {port}                                ║
║                                                          ║
║  Features:                                               ║
║  • Landing Page + Health Check                           ║
║  • Session Management API                                ║
║  • JWT/AccessToken Injection                             ║
║  • Active Session Validation                             ║
║                                                          ║
║  Proxy URL: https://proxy-url-by-harshu.onrender.com    ║
╚══════════════════════════════════════════════════════════╝
""")

sys.argv = [
    "mitmdump",
    "-s", "app.py",
    "-p", str(port),
    "--set", "block_global=false",
    "--set", "confdir=.",
]

try:
    from mitmproxy.tools.main import mitmdump
    mitmdump()
except ImportError as e:
    print(f"[ERROR] mitmproxy not installed: {e}")
    sys.exit(1)
except KeyboardInterrupt:
    print("\n[INFO] Shutting down...")
    sys.exit(0)
