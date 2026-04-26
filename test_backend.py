#!/usr/bin/env python3
"""
Simple test backend server for testing WAF proxy
Runs on port 8080
"""
from http.server import HTTPServer, SimpleHTTPRequestHandler

class TestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(b"""
<!DOCTYPE html>
<html>
<head>
    <title>Test Backend Server</title>
</head>
<body>
    <h1>Test Backend Server</h1>
    <p>This is a test backend running on port 8080.</p>
    <p>If you see this page, the WAF proxy is working correctly!</p>
</body>
</html>
        """)
    
    def log_message(self, format, *args):
        print(f"[Backend] {format % args}")

if __name__ == "__main__":
    server = HTTPServer(('localhost', 8080), TestHandler)
    print("Test backend server running on http://localhost:8080")
    print("Press Ctrl+C to stop")
    server.serve_forever()
