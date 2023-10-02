import json
import jwt
import base64
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from urllib.parse import parse_qs, urlparse


# Configuration
HOST = "localhost"
PORT = 8080
# Token expiration time in seconds (6 minutes)
EXPIRATION_SECONDS = 360  


# Generate a private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)


# Serialize the unexpired private key into PEM format
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)


# Generate an RSA key pair for the expired key
expired_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)


expired_public_key = expired_private_key.public_key()


# Serialize the expired key pair to PEM format
expired_private_key_pem = expired_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)


expired_public_key_pem = expired_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


# Define the key ID (kid) and token expiration timestamp
key_id = "my-key-id"
expiry_timestamp = int(time.time()) + EXPIRATION_SECONDS


# Create the JSON Web Key Set (JWKS) containing the public key
jwks = {
    "keys": [
        {
            "kid": key_id,
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": expired_public_key.public_numbers().n,
            "e": expired_public_key.public_numbers().e,
            "exp": expiry_timestamp
        }
    ]
}


# Define a custom HTTP request handler
class MyServer(BaseHTTPRequestHandler):
    # Handle GET requests
    def do_GET(self):
        if self.path == '/.well-known/jwks.json':
            # Respond with the JWKS JSON if the path is '/.well-known/jwks.json'
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            if int(time.time()) >= expiry_timestamp:
                # If the key has expired, return an error message
                self.wfile.write(json.dumps({"error": "Key has expired"}).encode('utf-8'))
            else:
                self.wfile.write(json.dumps(jwks).encode('utf-8'))
        else:
            # For other paths, return a simple HTML error message
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes("<html><head><title>Error</title></head>", "utf-8"))
            self.wfile.write(bytes("Please go to either of the two locations: <br> localhost:8080/.well-known/jwks.json <br> localhost:8080/auth", "utf-8"))


    # Handle POST requests
    def do_POST(self):
        if self.path.startswith('/auth'):
            # Check if the "expired" query parameter is present
            query_params = parse_qs(urlparse(self.path).query)
            expired_param = False
            if len(query_params) > 1:
                query_string = query_params[1]
                if "expired" in query_string:
                    expired_param = True


            # Respond with a JSON containing a JWT token
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            # Generate a JWT with the appropriate key and expiration
            key_to_use = expired_private_key_pem if expired_param else private_key_pem
            exp_to_use = expiry_timestamp if expired_param else (int(time.time()) + EXPIRATION_SECONDS)
            payload = {
                "sub": "user123",
                "exp": exp_to_use,
            }
            token = jwt.encode(payload, key_to_use, algorithm="RS256")
            response_data = {
                 "token": token,
                 "expired": expired_param
             }
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
        else:
            # Return a 405 (Method Not Allowed) response for other HTTP methods
            self.send_response(405)
            self.end_headers()


# Start the HTTP server
if __name__ == "__main__":
    webServer = HTTPServer((HOST, PORT), MyServer)
    print(f"Server started http://{HOST}:{PORT}")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()
    print("Server stopped.")
