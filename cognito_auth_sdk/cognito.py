"""
AWS Cognito JWT token verification using JWKS.
"""
import os
import jwt
import requests
from typing import Dict, Optional
from datetime import datetime, timedelta
from functools import lru_cache
from fastapi import HTTPException, status
from cognito_auth_sdk.schemas import TokenData


class CognitoJWTVerifier:
    """Verifies JWT tokens issued by AWS Cognito."""
    
    def __init__(self):
        self.region = os.getenv("AWS_REGION", "us-east-1")
        self.user_pool_id = os.getenv("COGNITO_USER_POOL_ID")
        self.app_client_id = os.getenv("COGNITO_APP_CLIENT_ID")
        
        if not self.user_pool_id or not self.app_client_id:
            raise ValueError("COGNITO_USER_POOL_ID and COGNITO_APP_CLIENT_ID must be set")
        
        self.jwks_url = f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}/.well-known/jwks.json"
        self.issuer = f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}"
        self._jwks_cache = None
        self._cache_time = None
    
    def _get_jwks(self) -> Dict:
        """Fetch JWKS from Cognito with 24-hour cache."""
        if self._jwks_cache and self._cache_time:
            if datetime.now() - self._cache_time < timedelta(hours=24):
                return self._jwks_cache
        
        try:
            response = requests.get(self.jwks_url, timeout=10)
            response.raise_for_status()
            self._jwks_cache = response.json()
            self._cache_time = datetime.now()
            return self._jwks_cache
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Failed to fetch JWKS: {str(e)}"
            )
    
    def _get_signing_key(self, token: str) -> str:
        """Get the public key for token verification."""
        try:
            # Decode header without verification to get kid
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            
            if not kid:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token missing kid in header"
                )
            
            # Find matching key in JWKS
            jwks = self._get_jwks()
            for key in jwks.get("keys", []):
                if key.get("kid") == kid:
                    return jwt.algorithms.RSAAlgorithm.from_jwk(key)
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unable to find matching key in JWKS"
            )
        except jwt.DecodeError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token format: {str(e)}"
            )
    
    def verify_token(self, token: str) -> TokenData:
        """
        Verify and decode a Cognito JWT token (access_token or id_token).

        Validates:
        - Signature using Cognito public keys
        - Token expiration
        - Issuer
        """
        try:
            signing_key = self._get_signing_key(token)

            # Decode without verification to check token type
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
            token_use = unverified_payload.get("token_use")

            if token_use == "id":
                # ID token: verify with audience (app_client_id)
                payload = jwt.decode(
                    token,
                    signing_key,
                    algorithms=["RS256"],
                    issuer=self.issuer,
                    audience=self.app_client_id,
                    options={
                        "verify_signature": True,
                        "verify_exp": True,
                        "verify_iss": True,
                        "verify_aud": True,
                    }
                )
            elif token_use == "access":
                # Access token: no audience claim, skip audience verification
                payload = jwt.decode(
                    token,
                    signing_key,
                    algorithms=["RS256"],
                    issuer=self.issuer,
                    options={
                        "verify_signature": True,
                        "verify_exp": True,
                        "verify_iss": True,
                        "verify_aud": False,
                    }
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type. Expected access_token or id_token."
                )

            # Check email verification - only for native users via id_token
            # Access tokens don't carry email_verified; we trust Cognito issued it
            email_verified = payload.get("email_verified", True)
            identities = payload.get("identities")

            if token_use == "id" and not identities and not email_verified:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Email not verified. Please verify your email"
                )

            return TokenData(
                sub=payload.get("sub"),
                email=payload.get("email", ""),
                given_name=payload.get("given_name"),
                family_name=payload.get("family_name"),
                name=payload.get("name"),
                email_verified=bool(email_verified),
                country_code=payload.get("custom:country_code"),
                contact_number=payload.get("custom:contact_number")
            )

        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.InvalidTokenError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {str(e)}"
            )
        except Exception as e:
            if isinstance(e, HTTPException):
                raise e
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token verification failed: {str(e)}"
            )
    


# Singleton instance
@lru_cache()
def get_cognito_verifier() -> CognitoJWTVerifier:
    """Get cached Cognito verifier instance."""
    return CognitoJWTVerifier()
