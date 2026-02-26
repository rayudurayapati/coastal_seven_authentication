"""
Auth request/response schemas.
"""
from pydantic import BaseModel, EmailStr, Field
from typing import Optional


class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=256)
    first_name: str = Field(..., min_length=1)
    last_name: str = Field(..., min_length=1)
    country_code: Optional[str] = None
    mobile_number: Optional[str] = None


class VerifyEmailRequest(BaseModel):
    email: EmailStr
    code: str = Field(..., min_length=6, max_length=6, example="123456")


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class OAuthLoginRequest(BaseModel):
    """For social login - exchange code for tokens."""
    code: str
    code_verifier: Optional[str] = ""


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    code: str = Field(..., min_length=6, max_length=6, description="Verification code must be 6 digits")
    new_password: str = Field(..., min_length=8, max_length=256, description="Password must be at least 8 characters long")


class ResendCodeRequest(BaseModel):
    email: EmailStr


class TokenResponse(BaseModel):
    """
    Returned on native login.
    Includes user_sub + email so developer can identify the logged-in user
    and look them up in their own DB.
    """
    access_token: str
    refresh_token: str
    expires_in: int
    token_type: str = "Bearer"
    user_sub: str
    email: str


class SocialLoginResponse(BaseModel):
    """
    Returned on social (Google/Facebook) login/signup.
    Includes tokens + user details so developer can create/fetch their DB row.
    """
    access_token: str
    refresh_token: str
    expires_in: int
    token_type: str = "Bearer"
    user_sub: str
    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None


class MessageResponse(BaseModel):
    message: str


class SignupResponse(BaseModel):
    """Returned on native signup - OTP sent, no user details yet (user not verified)."""
    message: str
    email: str


class ConfirmResponse(BaseModel):
    """
    Returned on native email confirmation (OTP verify).
    Developer should create their DB row here - this is the first point
    where the user is fully registered and verified.
    """
    message: str
    user_sub: str
    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    country_code: Optional[str] = None
    mobile_number: Optional[str] = None


class DeleteUserRequest(BaseModel):
    email: EmailStr
