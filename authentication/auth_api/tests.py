from django.test import TestCase, Client
from django.urls import reverse
from auth_api.models import CustomUser

class ViewTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.signup_url = reverse('signup')
        self.verify_email_url = reverse('verify')
        self.login_url = reverse('login')
    def test_signup(self):
        # Test valid signup
        data = {
            'username': 'testuser',
            'password': 'testpassword',
            'email': 'test@example.com'
        }
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json(), {'success': 'User registered successfully. Please check your email for verification.'})

        # Test invalid email
        data = {
            'username': 'testuser2',
            'password': 'testpassword',
            'email': 'invalidemail'
        }
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'error': 'Invalid email'})

        # Test existing email
        data = {
            'username': 'testuser3',
            'password': 'testpassword',
            'email': 'test@example.com'
        }
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'error': 'Email already exists'})

        # Test existing username
        data = {
            'username': 'testuser',
            'password': 'testpassword',
            'email': 'test2@example.com'
        }
        response = self.client.post(self.signup_url, data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'error': 'Username already exists'})

    def test_verify_email(self):
        # Create a user with a verification code
        user = CustomUser.objects.create_user(username='testuser', password='testpassword', email='test@example.com')
        user.verification_code = '123456'
        user.save()

        # Test valid verification code
        data = {'verification_code': '123456'}
        response = self.client.post(self.verify_email_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'success': 'Email verified successfully'})

        # Test invalid verification code
        data = {'verification_code': '654321'}
        response = self.client.post(self.verify_email_url, data)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'error': 'Invalid verification code'})
    
    def test_login_view_with_valid_credentials(self):
        # Create a user with valid credentials
        user = CustomUser.objects.create_user(
            username='testuser',
            password='testpassword',
            email='test@example.com'
        )
        user.is_active = True  # Set the user as active
        user.save()

        # Test login with valid credentials
        data = {
            'username': 'testuser',
            'password': 'testpassword'
        }
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, 200)
        self.assertIn('private_key', response.json())
        self.assertIn('public_key', response.json())
        
    def test_login_view_with_invalid_credentials(self):
        # Test login with invalid credentials
        data = {
            'username': 'testuser',
            'password': 'wrongpassword'
        }
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {'error': 'Invalid username or password'})
    def test_login_view_with_inactive_user(self):
        # Create an inactive user
        user = CustomUser.objects.create_user(
            username='testuser',
            password='testpassword',
            email='test@example.com'
        )
        user.is_active = False  # Set the user as inactive
        user.save()

        # Test login with inactive user
        data = {
            'username': 'testuser',
            'password': 'testpassword'
        }
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {'error': 'Email not confirmed'})
    def test_login_view_with_nonexistent_user(self):
        # Test login with nonexistent user
        data = {
            'username': 'nonexistentuser',
            'password': 'testpassword'
        }
        response = self.client.post(self.login_url, data)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {'error': 'Invalid username or password'})
   