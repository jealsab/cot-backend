from django.test import TestCase, Client
from django.urls import reverse
from auth_api.models import CustomUser

class AuthenticationTestCase(TestCase):
    def setUp(self):
        self.client = Client()

    
    def test_signup(self):
        # Test signup functionality
        url = reverse('signup')
        data = {
            'username': 'testuser',
            'password': 'testpassword',
            'email': 'test@example.com'
        }
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'message': 'Signup successful'})

        # Verify that the user is created
        user = CustomUser.objects.get(username='testuser')
        self.assertEqual(user.username, 'testuser')
        self.assertTrue(user.check_password('testpassword'))
        self.assertEqual(user.email, 'test@example.com')

    def test_login(self):
        # Create a user for testing
        user = CustomUser.objects.create_user(username='testuser', password='testpassword', email='test@example.com')

        # Test login functionality
        url = reverse('login')
        data = {
            'username': 'testuser',
            'password': 'testpassword'
        }
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['private_key'], user.private_key)
        self.assertEqual(response.json()['public_key'], user.public_key)

    def test_invalid_login(self):
        # Test login with invalid credentials
        url = reverse('login')
        data = {
            'username': 'testuser',
            'password': 'wrongpassword'
        }
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {'error': 'Invalid username or password'})