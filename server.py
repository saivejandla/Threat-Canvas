#!/usr/bin/env python3
"""Dev server with no-cache headers — prevents browser from serving stale JS."""
import http.server, sys

class NoCacheHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()
    def log_message(self, fmt, *args):
        pass  # suppress request spam

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8082
print(f'Serving on http://localhost:{port}  (no-cache mode)')
http.server.HTTPServer(('', port), NoCacheHandler).serve_forever()
