"""
Authentication API endpoints.
No database dependency - SDK is DB-agnostic.
Developers handle their own DB operations using the data returned by these endpoints.
"""
import os
import logging
from fastapi import APIRouter, Depends, HTTPException, status, Request

from cognito_auth_sdk.cognito_service import get_cognito_service, CognitoService
from cognito_auth_sdk.dependencies import get_current_user
from cognito_auth_sdk.auth_schemas import (
    SignupRequest, SignupResponse,
    VerifyEmailRequest, MessageResponse,
    LoginRequest, OAuthLoginRequest, TokenResponse,
    SocialLoginResponse, ConfirmResponse,
    RefreshTokenRequest,
    ForgotPasswordRequest, ResetPasswordRequest,
    ResendCodeRequest
)
from cognito_auth_sdk.cognito import get_cognito_verifier

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


# ─────────────────────────────────────────────
# SOCIAL LOGIN ENDPOINTS (Google / Facebook)
# ─────────────────────────────────────────────

@router.post("/login", response_model=SocialLoginResponse)
async def oauth_login(
    req: Request,
    request: OAuthLoginRequest,
    cognito: CognitoService = Depends(get_cognito_service),
    verifier=Depends(get_cognito_verifier)
):
    """
    Social Login (Google/Facebook) - Exchange authorization code for tokens.

    Returns tokens + user details so the developer can create/fetch their DB row.
    - First-time social login: developer creates a DB row using user_sub + email + name
    - Returning social user: developer fetches existing DB row by user_sub
    """
    try:
        origin = req.headers.get("origin", "")
        redirect_uri = origin + os.getenv("OAUTH_REDIRECT_URI", "")

        if not redirect_uri.strip("/"):
            logger.error("OAuth login failed: OAUTH_REDIRECT_URI not configured")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="OAUTH_REDIRECT_URI not configured in environment"
            )

        # Exchange code for tokens
        tokens = cognito.exchange_code_for_tokens(
            code=request.code,
            code_verifier=request.code_verifier,
            redirect_uri=redirect_uri
        )

        # Verify ID token to extract user claims
        token_data = verifier.verify_token(tokens["id_token"])

        # Parse name fields
        first_name = token_data.given_name
        last_name = token_data.family_name
        if not first_name and token_data.name:
            parts = token_data.name.split(" ", 1)
            first_name = parts[0]
            last_name = parts[1] if len(parts) > 1 else ""

        logger.info(f"Social login successful - {token_data.email}")

        return {
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "expires_in": tokens["expires_in"],
            "token_type": "Bearer",
            "user_sub": str(token_data.sub),
            "email": token_data.email,
            "first_name": first_name,
            "last_name": last_name,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Social login failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Social login failed: {str(e)}"
        )


@router.post("/signup", response_model=SocialLoginResponse)
async def oauth_signup(
    req: Request,
    request: OAuthLoginRequest,
    cognito: CognitoService = Depends(get_cognito_service),
    verifier=Depends(get_cognito_verifier)
):
    """
    Social Signup (Google/Facebook) - Same as social login.
    Cognito treats first-time social login as signup automatically.
    """
    return await oauth_login(req, request, cognito, verifier)


# ─────────────────────────────────────────────
# TOKEN VALIDATION
# ─────────────────────────────────────────────

@router.get("/validate-token")
async def validate_token(
    token_data=Depends(get_current_user)
):
    """
    Validate JWT token sent in Authorization header.
    Returns Cognito claims if token is valid - no DB lookup needed.
    """
    return {
        "valid": True,
        "user_sub": str(token_data.sub),
        "email": token_data.email,
    }


# ─────────────────────────────────────────────
# NATIVE ENDPOINTS (Email / Password)
# ─────────────────────────────────────────────

@router.post("/native/signup", response_model=SignupResponse, status_code=status.HTTP_201_CREATED)
async def native_signup(
    request: SignupRequest,
    cognito: CognitoService = Depends(get_cognito_service)
):
    """
    Sign up a new user with email and password.

    Returns only a success message + email.
    User is NOT verified yet - do NOT create a DB row here.
    Wait for /native/confirm to get full user details.
    """
    try:
        result = cognito.signup(
            email=request.email,
            password=request.password,
            first_name=request.first_name,
            last_name=request.last_name,
            country_code=request.country_code,
            contact_number=request.mobile_number
        )
        logger.info(f"Native signup successful - {request.email}")
        # Return only message + email, strip user_sub — user is unverified
        return {
            "message": "OTP sent successfully. Please check your email to verify your account.",
            "email": request.email
        }
    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e)
        if "failed to satisfy constraint" in error_msg and "password" in error_msg.lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password cannot be empty"
            )
        logger.error(f"Native signup failed - {request.email}: {str(e)}")
        raise


@router.post("/native/confirm", response_model=ConfirmResponse)
async def native_confirm(
    request: VerifyEmailRequest,
    cognito: CognitoService = Depends(get_cognito_service)
):
    """
    Verify email with OTP code sent to user's email.

    ✅ THIS is where the developer should create their DB row.
    Returns full user details: user_sub, email, first_name, last_name, country_code, mobile_number.
    User is now fully registered and verified.
    """
    try:
        # Verify email OTP in Cognito
        cognito.verify_email(email=request.email, code=request.code)

        # Fetch full user attributes from Cognito after successful verification
        user_info = cognito.get_user_info(request.email)
        attrs = user_info.get("attributes", {}) if user_info else {}

        logger.info(f"Email verified successfully - {request.email}")

        return {
            "message": "Email verified successfully. You can now login.",
            "user_sub": attrs.get("sub", ""),
            "email": attrs.get("email", request.email),
            "first_name": attrs.get("given_name"),
            "last_name": attrs.get("family_name"),
            "country_code": attrs.get("custom:country_code"),
            "mobile_number": attrs.get("custom:contact_number"),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email verification failed - {request.email}: {str(e)}")
        raise


@router.post("/native/login", response_model=TokenResponse)
async def native_login(
    request: LoginRequest,
    cognito: CognitoService = Depends(get_cognito_service)
):
    """
    Login with email and password.

    Returns tokens + user_sub and email so developer can identify the logged-in user.
    Social users are blocked here with a clear error message.
    """
    try:
        tokens = cognito.login(
            email=request.email,
            password=request.password
        )

        # Fetch user info from Cognito to get user_sub + email for the developer
        user_info = cognito.get_user_info(request.email)
        attrs = user_info.get("attributes", {}) if user_info else {}

        logger.info(f"Native login successful - {request.email}")
        return {
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "expires_in": tokens["expires_in"],
            "token_type": "Bearer",
            "user_sub": attrs.get("sub", ""),
            "email": attrs.get("email", request.email),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Native login failed - {request.email}: {str(e)}")
        raise


@router.post("/native/forgot-password", response_model=MessageResponse)
async def native_forgot_password(
    request: ForgotPasswordRequest,
    cognito: CognitoService = Depends(get_cognito_service)
):
    """
    Send password reset OTP to user's email.
    Social users are blocked here with a clear error message.
    """
    try:
        result = cognito.forgot_password(request.email)
        logger.info(f"Forgot password OTP sent - {request.email}")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Forgot password failed - {request.email}: {str(e)}")
        raise


@router.post("/native/confirm-forgot-password", response_model=MessageResponse)
async def native_confirm_forgot_password(
    request: ResetPasswordRequest,
    cognito: CognitoService = Depends(get_cognito_service)
):
    """
    Reset password using OTP from email.
    """
    try:
        result = cognito.reset_password(
            email=request.email,
            code=request.code,
            new_password=request.new_password
        )
        logger.info(f"Password reset successful - {request.email}")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password reset failed - {request.email}: {str(e)}")
        raise


@router.post("/native/resend-code", response_model=MessageResponse)
async def native_resend_code(
    request: ResendCodeRequest,
    cognito: CognitoService = Depends(get_cognito_service)
):
    """
    Resend OTP verification code to user's email.
    """
    try:
        result = cognito.resend_verification_code(request.email)
        logger.info(f"Verification code resent - {request.email}")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Resend verification code failed - {request.email}: {str(e)}")
        raise
