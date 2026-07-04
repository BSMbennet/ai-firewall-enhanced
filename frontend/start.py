import os
import sys
import http.server
import socketserver

# 1. Setup Configuration
PORT = int(os.environ.get("PORT", 8080))

# 2. Debugging & Directory Check
print(f"Current directory: {os.getcwd()}")
print(f"Files here: {os.listdir('.')}")

# If you are in the app root but 'build' is inside 'ai-firewall/frontend'
# manually adjust path if needed, but normally 'build' should be here.
if not os.path.exists('build'):
    print(f"❌ ERROR: 'build' directory not found!")
    print(f"📁 Current contents: {os.listdir('.')}")
    sys.exit(1)

# 3. Change to build directory BEFORE starting the server
os.chdir('build')
print(f"✅ Serving files from: {os.getcwd()}")

# 4. Define the Handler
Handler = http.server.SimpleHTTPRequestHandler
Handler.extensions_map.update({
    '.js': 'application/javascript',
    '.css': 'text/css',
    '.html': 'text/html',
})

# 5. Start the server (Must be 0.0.0.0 for Railway)
print(f"🚀 Frontend server starting on port {PORT}")
with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
    httpd.serve_forever()
