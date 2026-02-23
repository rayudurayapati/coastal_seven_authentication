"""
Auth-related Pydantic schemas for request/response validation.
"""
from pydantic import BaseModel, EmailStr
from typing import Optional
from uuid import UUID


class TokenData(BaseModel):
    """Data extracted from a verified Cognito JWT (access_token or id_token)."""
    sub: UUID
    email: str
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    name: Optional[str] = None
    email_verified: bool = False
    country_code: Optional[str] = None
    contact_number: Optional[str] = None

