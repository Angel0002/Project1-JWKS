import json
import unittest
import base64
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from server import app, generate_jwt  # Import your Flask app and the generate_jwt function

# Define a class for your unit tests
class TestServer(unittest.TestCase):
    def setUp(self):
        # Create a test client
        self.app = app.test_client()

    # Test the '/auth' route for generating JWTs
    def test_auth_route(self):
        response = self.app.post('/auth')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertIn('access_token', data)

    # Test the '/auth' route with the "expired" query parameter
    def test_expired_auth_route(self):
        response = self.app.post('/auth?expired=true')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertIn('access_token', data)

    # Test JWT generation using an expired key
    def test_expired_jwt_generation(self):
        key_id = "kid_0"
        token = generate_jwt(keys[key_id]["private_key"], key_id, expired=True)
        self.assertIsNotNone(token)

    # Test the '/auth/.well-known/jwks.json' route for returning JWKS
    def test_get_jwks_route(self):
        response = self.app.get('/auth/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        jwks_data = json.loads(response.data.decode('utf-8'))
        self.assertIn('keys', jwks_data)
        self.assertIsInstance(jwks_data['keys'], list)

    # Test with an invalid Authorization header format
    def test_invalid_auth_header(self):
        response = self.app.post(
            '/auth',
            headers={'Authorization': 'InvalidHeaderFormat'}
        )
        self.assertEqual(response.status_code, 401)

    # Test with an empty Authorization header
    def test_empty_auth_header(self):
        response = self.app.post(
            '/auth',
            headers={'Authorization': ''}
        )
        self.assertEqual(response.status_code, 401)

    # Test without an Authorization header
    def test_no_auth_header(self):
        response = self.app.post('/auth')
        self.assertEqual(response.status_code, 401)

    # Test authentication with an expired token
    def test_expired_token(self):
        username = "userABC"
        password = "password123"
        credentials = base64.b64encode(
            f"{username}:{password}".encode()).decode()
        # Create an expired token manually for testing
        expired_token = generate_jwt(keys["kid_0"]["private_key"], "kid_0", expired=True)
        response = self.app.post(
            '/auth',
            headers={'Authorization': f'Bearer {expired_token}'}
        )
        self.assertEqual(response.status_code, 401)

    # Test accessing an unauthorized endpoint without authentication
    def test_unauthorized_endpoint(self):
        response = self.app.get('/protected_endpoint')
        self.assertEqual(response.status_code, 401)

    # Test accessing an authorized endpoint with valid authentication
    def test_authorized_endpoint(self):
        username = "userABC"
        password = "password123"
        credentials = base64.b64encode(
            f"{username}:{password}".encode()).decode()
        response = self.app.get('/protected_endpoint',
                                headers={'Authorization': f'Basic {credentials}'})
        self.assertEqual(response.status_code, 200)
        # Add more assertions to check the response content if needed

if __name__ == '__main__':
    unittest.main()
