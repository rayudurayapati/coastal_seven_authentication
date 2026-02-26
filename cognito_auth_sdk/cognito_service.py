"""
AWS Cognito Service - Handles all Cognito operations.
"""
import os
import boto3
import logging
from botocore.exceptions import ClientError
from typing import Dict, Optional
from fastapi import HTTPException, status

logger = logging.getLogger(__name__)


class CognitoService:
    """Service to interact with AWS Cognito."""
    
    def __init__(self):
        self.region = os.getenv("AWS_REGION", "us-east-1")
        self.user_pool_id = os.getenv("COGNITO_USER_POOL_ID")
        self.app_client_id = os.getenv("COGNITO_APP_CLIENT_ID")
        self.cognito_domain = os.getenv("COGNITO_DOMAIN")
        
        if not all([self.user_pool_id, self.app_client_id]):
            raise ValueError("COGNITO_USER_POOL_ID and COGNITO_APP_CLIENT_ID must be set")
        
        self.client = boto3.client('cognito-idp', region_name=self.region)
    
    def signup(self, email: str, password: str, first_name: str, last_name: str, country_code: str = None, contact_number: str = None) -> Dict:
        """
        Sign up a new user in Cognito.
        Sends verification email automatically.
        """
        # Check if user already exists
        user_info = self.get_user_info(email)
        
        if user_info:
            user_status = user_info.get('user_status')
            
            # Check if user is from social login
            if self.is_social_user(user_info):
                provider = self.get_social_provider(user_info)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"An account with this email already exists. Please sign in with {provider}."
                )
            
            # Check if user is unconfirmed
            if user_status == 'UNCONFIRMED':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="You have an unconfirmed account. Please check your email for the verification code or request a new one."
                )
            
            # User exists and is confirmed
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists. Please sign in instead."
            )
        
        try:
            user_attributes = [
                {'Name': 'email', 'Value': email},
                {'Name': 'name', 'Value': f"{first_name} {last_name}"},
                {'Name': 'given_name', 'Value': first_name},
                {'Name': 'family_name', 'Value': last_name}
            ]
            
            response = self.client.sign_up(
                ClientId=self.app_client_id,
                Username=email,
                Password=password,
                UserAttributes=user_attributes
            )
            
            logger.info(f"User signed up successfully: {email}")
            
            return {
                "message": "User created successfully. Please check your email for verification code.",
                "user_sub": response['UserSub'],
                "email": email
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            logger.error(f"Signup failed for {email}: {error_code}")
            
            if error_code == 'UsernameExistsException':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User with this email already exists"
                )
            elif error_code == 'InvalidPasswordException':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Password must contain at least 8 characters, including uppercase, lowercase, number, and special character"
                )
            elif error_code == 'InvalidParameterException':
                error_message = str(e.response['Error']['Message'])
                if "password" in error_message.lower() and "constraint" in error_message.lower():
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Password must contain at least 8 characters, including uppercase, lowercase, number, and special character"
                    )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=error_message
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Signup failed: {str(e)}"
                )

    def signup_confirmed(self, email: str, password: str, first_name: str, last_name: str, country_code: str = None, contact_number: str = None) -> Dict:
        """
        Sign up a user and immediately confirm them, bypassing OTP.
        """
        # Check if user already exists
        user_info = self.get_user_info(email)
        
        if user_info:
            user_status = user_info.get('user_status')
            
            # Check if user is from social login
            if self.is_social_user(user_info):
                provider = self.get_social_provider(user_info)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"An account with this email already exists. Please sign in with {provider}."
                )
            
            # Check if user is unconfirmed
            if user_status == 'UNCONFIRMED':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="You already have an unconfirmed account. Please check your email for the verification code or request a new one."
                )
            
            # User exists and is confirmed
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exists."
            )
        
        try:
            user_attributes = [
                {'Name': 'email', 'Value': email},
                {'Name': 'email_verified', 'Value': 'true'},
                {'Name': 'name', 'Value': f"{first_name} {last_name}"},
                {'Name': 'given_name', 'Value': first_name},
                {'Name': 'family_name', 'Value': last_name}
            ]
            
            if country_code:
                user_attributes.append({'Name': 'custom:country_code', 'Value': country_code})
            if contact_number:
                user_attributes.append({'Name': 'custom:contact_number', 'Value': contact_number})
            
            response = self.client.admin_create_user(
                UserPoolId=self.user_pool_id,
                Username=email,
                UserAttributes=user_attributes,
                MessageAction='SUPPRESS' # Do not send welcome email
            )
            
            user_sub = next((attr['Value'] for attr in response['User']['Attributes'] if attr['Name'] == 'sub'), None)
            
            # Set permanent password so they don't have to change it on first login
            self.client.admin_set_user_password(
                UserPoolId=self.user_pool_id,
                Username=email,
                Password=password,
                Permanent=True
            )
            
            logger.info(f"User signed up and confirmed successfully: {email}")
            
            return {
                "message": "User created and verified successfully.",
                "user_sub": user_sub,
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "country_code": country_code,
                "mobile_number": contact_number,
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            logger.error(f"Confirmed signup failed for {email}: {error_code}")
            
            if error_code == 'UsernameExistsException':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User with this email already exists"
                )
            elif error_code in ['InvalidPasswordException', 'InvalidParameterException']:
                error_message = str(e.response['Error']['Message'])
                if "password" in error_message.lower():
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Password must contain at least 8 characters, including uppercase, lowercase, number, and special character"
                    )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=error_message
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Signup failed: {str(e)}"
                )

    def delete_user(self, email: str) -> Dict:
        """
        Delete a user from Cognito.
        """
        # Check if user exists
        user_info = self.get_user_info(email)
        
        if not user_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found."
            )
            
        try:
            self.client.admin_delete_user(
                UserPoolId=self.user_pool_id,
                Username=email
            )
            
            logger.info(f"User deleted successfully: {email}")
            return {"message": "User deleted successfully."}
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            logger.error(f"Delete user failed for {email}: {error_code}")
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Delete user failed: {str(e)}"
            )
    
    def verify_email(self, email: str, code: str) -> Dict:
        """Confirm user email with verification code."""
        try:
            self.client.confirm_sign_up(
                ClientId=self.app_client_id,
                Username=email,
                ConfirmationCode=code
            )
            
            logger.info(f"Email verified: {email}")
            return {"message": "Email verified successfully. You can now login."}
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            logger.error(f"Email verification failed for {email}: {error_code}")
            
            if error_code == 'CodeMismatchException':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid verification code"
                )
            elif error_code == 'ExpiredCodeException':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Verification code has expired"
                )
            elif error_code == 'NotAuthorizedException':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User is already verified"
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Verification failed: {str(e)}"
                )
    
    def login(self, email: str, password: str) -> Dict:
        """Login user with email and password."""
        # Check if user exists in Cognito first
        user_info = self.get_user_info(email)
        
        if not user_info:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email does not exist. Please sign up first."
            )
        
        # Check if user is from social login
        if self.is_social_user(user_info):
            provider = self.get_social_provider(user_info)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"This account was created with {provider}. Please sign in with {provider} instead."
            )
        
        # Check if user is unconfirmed
        if user_info.get('user_status') == 'UNCONFIRMED':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You have an unconfirmed account. Please check your email for the verification code or request a new one."
            )
        
        try:
            response = self.client.initiate_auth(
                ClientId=self.app_client_id,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': email,
                    'PASSWORD': password
                }
            )
            
            auth_result = response['AuthenticationResult']
            
            logger.info(f"Login successful: {email}")
            
            return {
                "access_token": auth_result['AccessToken'],
                "refresh_token": auth_result['RefreshToken'],
                "expires_in": auth_result['ExpiresIn'],
                "token_type": "Bearer"
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            logger.error(f"Login failed for {email}: {error_code}")
            
            if error_code == 'NotAuthorizedException':
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect email or password"
                )
            elif error_code == 'UserNotConfirmedException':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email not verified. Please verify your email first."
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Login failed: {str(e)}"
                )


    def exchange_code_for_tokens(self, code: str, code_verifier: str, redirect_uri: str) -> Dict:
        """
        Exchange OAuth authorization code for tokens (Social Login).
        Used after Google/Facebook login via Cognito Hosted UI.
        """
        try:
            import requests
            
            token_url = f"https://{self.cognito_domain}/oauth2/token"
            
            data = {
                'grant_type': 'authorization_code',
                'client_id': self.app_client_id,
                'code': code,
                'code_verifier': code_verifier,
                'redirect_uri': redirect_uri
            }
            
            response = requests.post(token_url, data=data)
            
            if response.status_code != 200:
                logger.error(f"OAuth token exchange failed - Status: {response.status_code}, Error: {response.text}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Failed to exchange code for tokens: {response.text}"
                )
            
            tokens = response.json()
            logger.info(f"OAuth token exchange successful")
            
            return {
                "access_token": tokens['access_token'],
                "id_token": tokens['id_token'],
                "refresh_token": tokens['refresh_token'],
                "expires_in": tokens['expires_in'],
                "token_type": "Bearer"
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"OAuth token exchange request failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Token exchange failed: {str(e)}"
            )
        except Exception as e:
            logger.error(f"OAuth token exchange unexpected error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Token exchange failed: {str(e)}"
            )
    
    def refresh_token(self, refresh_token: str) -> Dict:
        """Refresh access token using refresh token."""
        try:
            response = self.client.initiate_auth(
                ClientId=self.app_client_id,
                AuthFlow='REFRESH_TOKEN_AUTH',
                AuthParameters={
                    'REFRESH_TOKEN': refresh_token
                }
            )
            
            auth_result = response['AuthenticationResult']
            
            return {
                "access_token": auth_result['AccessToken'],
                "id_token": auth_result['IdToken'],
                "expires_in": auth_result['ExpiresIn'],
                "token_type": "Bearer"
            }
            
        except ClientError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token"
            )
    
    def logout(self, access_token: str) -> Dict:
        """Logout user and invalidate all tokens."""
        try:
            self.client.global_sign_out(
                AccessToken=access_token
            )
            
            return {"message": "Logged out successfully"}
            
        except ClientError as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Logout failed: {str(e)}"
            )
    
    def forgot_password(self, email: str) -> Dict:
        """Send password reset code to user's email."""
        # Check if user exists and their type
        user_info = self.get_user_info(email)
        
        if not user_info:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email does not exist. Please sign up first."
            )
        
        # Check if user is unconfirmed
        if user_info.get('user_status') == 'UNCONFIRMED':
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Your account is not verified. Please check your email for the verification code or request a new one to complete signup."
            )
        
        # Check if user is from social login
        if self.is_social_user(user_info):
            provider = self.get_social_provider(user_info)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"This account was created with {provider}. Password reset is not available for social login accounts. Please sign in with {provider}."
            )
        
        try:
            self.client.forgot_password(
                ClientId=self.app_client_id,
                Username=email
            )
            
            return {"message": "Password reset code sent to your email"}
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            logger.error(f"Forgot password failed: {error_code}")
            
            if error_code == 'InvalidParameterException':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Your account is not verified. Please verify your email first before resetting password."
                )
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to send reset code: {str(e)}"
            )
    
    def reset_password(self, email: str, code: str, new_password: str) -> Dict:
        """Reset password using verification code."""
        try:
            self.client.confirm_forgot_password(
                ClientId=self.app_client_id,
                Username=email,
                ConfirmationCode=code,
                Password=new_password
            )
            
            return {"message": "Password reset successfully. You can now login with your new password."}
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            
            if error_code == 'CodeMismatchException':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid reset code"
                )
            elif error_code == 'ExpiredCodeException':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Reset code has expired"
                )
            elif error_code == 'InvalidPasswordException':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Password must contain at least 8 characters, including uppercase, lowercase, number, and special character"
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Password reset failed: {str(e)}"
                )
    
    def resend_verification_code(self, email: str) -> Dict:
        """Resend email verification code."""
        try:
            self.client.resend_confirmation_code(
                ClientId=self.app_client_id,
                Username=email
            )
            
            return {"message": "Verification code sent to your email"}
            
        except ClientError as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to resend code: {str(e)}"
            )
    
    def get_user_info(self, email: str) -> Optional[Dict]:
        """
        Get user information from Cognito.
        Returns None if user doesn't exist.
        """
        try:
            response = self.client.admin_get_user(
                UserPoolId=self.user_pool_id,
                Username=email
            )
            
            attributes = {attr['Name']: attr['Value'] for attr in response.get('UserAttributes', [])}
            
            return {
                'username': response.get('Username'),
                'user_status': response.get('UserStatus'),
                'enabled': response.get('Enabled', True),
                'attributes': attributes,
                'identities': attributes.get('identities')
            }
        except ClientError as e:
            if e.response['Error']['Code'] == 'UserNotFoundException':
                return None
            raise
    
    def is_social_user(self, user_info: Dict) -> bool:
        """Check if user signed up via social provider."""
        identities = user_info.get('attributes', {}).get('identities')
        return identities is not None
    
    def get_social_provider(self, user_info: Dict) -> Optional[str]:
        """Get social provider name (Google, Facebook, etc)."""
        identities = user_info.get('attributes', {}).get('identities')
        if identities:
            import json
            try:
                identity_list = json.loads(identities)
                if identity_list and len(identity_list) > 0:
                    provider = identity_list[0].get('providerName', 'Social')
                    return provider
            except:
                return 'Social'
        return None


# Singleton instance
_cognito_service = None

def get_cognito_service() -> CognitoService:
    """Get cached Cognito service instance."""
    global _cognito_service
    if _cognito_service is None:
        _cognito_service = CognitoService()
    return _cognito_service
