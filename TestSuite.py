# EUID: mv0487
# Name: Vineeth Reddy

import unittest
import requests

class TestEndpoints(unittest.TestCase):
    def setUp(self):
        self.base_url = "http://localhost:8080"

    def test_authentication_success(self):
        data = {"username": "test_user", "password": "test_password"}
        response = requests.post(f"{self.base_url}/auth", json=data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("token", response.json())

    def test_registration_success(self):
        data = {"username": "new_user", "password": "new_password"}
        response = requests.post(f"{self.base_url}/register", json=data)
        self.assertEqual(response.status_code, 201)
        self.assertIn("message", response.json())

    def test_registration_failure_duplicate(self):
        data = {"username": "new_user", "password": "new_password"}
        response = requests.post(f"{self.base_url}/register", json=data)
        self.assertEqual(response.status_code, 409)

if __name__ == "__main__":
    unittest.main()
# EUID: mv0487
# Name: Vineeth Reddy

import unittest
import requests

class TestEndpoints(unittest.TestCase):
    def setUp(self):
        self.base_url = "http://localhost:8080"

    def test_authentication_success(self):
        data = {"username": "test_user", "password": "test_password"}
        response = requests.post(f"{self.base_url}/auth", json=data)
        self.assertEqual(response.status_code, 200)
        self.assertIn("token", response.json())

    def test_registration_success(self):
        data = {"username": "new_user", "password": "new_password"}
        response = requests.post(f"{self.base_url}/register", json=data)
        self.assertEqual(response.status_code, 201)
        self.assertIn("message", response.json())

    def test_registration_failure_duplicate(self):
        data = {"username": "new_user", "password": "new_password"}
        response = requests.post(f"{self.base_url}/register", json=data)
        self.assertEqual(response.status_code, 409)

if __name__ == "__main__":
    unittest.main()
