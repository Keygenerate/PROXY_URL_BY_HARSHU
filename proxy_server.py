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
║           FREE FIRE PROXY SERVER                         ║
║                                                          ║
║  CREATE BY HARSHU                                        ║
║  Running on port: {port}                                ║
║                                                          ║
║  Copy this URL and set in your API:                     ║
║  POST /api/proxy                                        ║
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
