import http.server
import urllib.request
import socketserver
import logging

# Configuration
PORT = 8080
SAFE_SITES = ["google.com", "github.com", "wikipedia.org"]
BLACKLISTED_SITES = ["malicious-example.com", "scam-site.net"]

# Setup Logging to a file
logging.basicConfig(filename='proxy_access.log', level=logging.INFO, 
                    format='%(asctime)s - Request: %(message)s')

class SecurityProxy(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # 1. Log the requested website
        logging.info(self.path)
        print(f"Checking access for: {self.path}")

        # 2. Block reported malicious websites
        if any(bad_site in self.path for bad_site in BLACKLISTED_SITES):
            self.send_error(403, "Access Blocked: Site is on the malicious blacklist.")
            return

        # 3. Security Filter: Only HTTPS or Safe List
        is_https = self.path.startswith("https://")
        is_safe_listed = any(safe_site in self.path for safe_site in SAFE_SITES)

        if not (is_https or is_safe_listed):
            self.send_error(403, "Access Denied: Only HTTPS or Safe-Listed sites allowed.")
            return

        # 4. IP Masking: Proxy fetches the content on its own
        try:
            # We use a User-Agent to look like a standard browser request
            req = urllib.request.Request(self.path, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as response:
                self.send_response(response.status)
                for header, value in response.getheaders():
                    self.send_header(header, value)
                self.end_headers()
                self.wfile.write(response.read())
        except Exception as e:
            self.send_error(500, f"Proxy Error: {e}")

# Start the server
with socketserver.TCPServer(("", PORT), SecurityProxy) as httpd:
    print(f"Security Proxy active on port {PORT}")
    httpd.serve_forever()
