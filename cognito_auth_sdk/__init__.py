"""
Cognito Auth SDK - AWS Cognito Authentication for FastAPI

Provides:
1. Token verification for protected endpoints (DB-agnostic, returns TokenData)
2. Cognito service for auth operations
3. FastAPI routes for authentication
4. Pydantic schemas for request/response validation
"""

__version__ = "1.1.0"

# Token verification (for protected endpoints)
from .dependencies import (
    get_current_user,
    get_current_active_user,
    extract_token_from_request,
    websocket_authenticate,
    get_current_user_ws,
)
from .cognito import CognitoJWTVerifier, get_cognito_verifier
from .schemas import TokenData

# Cognito service
from .cognito_service import CognitoService, get_cognito_service

# Auth routes
from .routes import router as auth_router

# Schemas
from .auth_schemas import (
    SignupRequest, SignupResponse,
    VerifyEmailRequest, ConfirmResponse,
    MessageResponse,
    LoginRequest, OAuthLoginRequest,
    TokenResponse, SocialLoginResponse,
    RefreshTokenRequest,
    ForgotPasswordRequest, ResetPasswordRequest,
    ResendCodeRequest
)

__all__ = [
    # Version
    "__version__",
    # Token verification
    "get_current_user",
    "get_current_active_user",
    "extract_token_from_request",
    "websocket_authenticate",
    "get_current_user_ws",
    "CognitoJWTVerifier",
    "get_cognito_verifier",
    "TokenData",
    # Cognito service
    "CognitoService",
    "get_cognito_service",
    # Routes
    "auth_router",
    # Schemas
    "SignupRequest",
    "SignupResponse",
    "VerifyEmailRequest",
    "ConfirmResponse",
    "MessageResponse",
    "LoginRequest",
    "OAuthLoginRequest",
    "TokenResponse",
    "SocialLoginResponse",
    "RefreshTokenRequest",
    "ForgotPasswordRequest",
    "ResetPasswordRequest",
    "ResendCodeRequest",
]
