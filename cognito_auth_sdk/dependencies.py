"""
FastAPI dependencies for authentication.

No database dependency - SDK is DB-agnostic.
get_current_user returns TokenData (Cognito claims).
Developers use token_data.sub and token_data.email to look up their own DB.
"""
import logging
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer

from cognito_auth_sdk.cognito import get_cognito_verifier, CognitoJWTVerifier
from cognito_auth_sdk.schemas import TokenData

logger = logging.getLogger(__name__)

# This dummy bearer is purely to force Swagger UI to show the "Authorize" button
oauth2_scheme = HTTPBearer(auto_error=False)

def extract_token_from_request(request: Request) -> str:
    """
    Extract JWT token from request.
    Priority: Authorization header > user-token cookie
    """
    # Try Authorization header first (primary method)
    auth_header = request.headers.get("Authorization")
    if auth_header:
        parts = auth_header.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Use: Bearer <token>"
        )

    # Fallback to cookie
    token = request.cookies.get("user-token")
    if token:
        return token

    # No token found
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. No token provided",
        headers={"WWW-Authenticate": "Bearer"}
    )


from fastapi.security import HTTPAuthorizationCredentials

def get_current_user(
    request: Request,
    verifier: CognitoJWTVerifier = Depends(get_cognito_verifier),
    token_auth: HTTPAuthorizationCredentials = Depends(oauth2_scheme)
) -> TokenData:
    """
    Verify JWT token and return Cognito claims (TokenData).

    No DB lookup - SDK is DB-agnostic.
    Use token_data.sub and token_data.email to look up your own DB:

        @router.get("/me")
        def get_me(token_data: TokenData = Depends(get_current_user), db: Session = Depends(get_db)):
            user = db.query(User).filter(User.cognito_sub == str(token_data.sub)).first()
            ...
    """
    # Use the token extracted by FastAPI's HTTPBearer if available
    # Otherwise fallback to manual extraction (for cookies)
    token = token_auth.credentials if token_auth else extract_token_from_request(request)
    token_data: TokenData = verifier.verify_token(token)
    return token_data


def get_current_active_user(
    token_data: TokenData = Depends(get_current_user)
) -> TokenData:
    """
    Alias for get_current_user. Use for endpoints requiring active users.
    Add your own is_active check against your DB after fetching the user.
    """
    return token_data


# ─────────────────────────────────────────────
# WebSocket Authentication
# ─────────────────────────────────────────────

async def get_token_from_query(query_params: dict) -> str:
    """
    Extract JWT token from WebSocket query parameters.
    Usage: ws://localhost:8000/ws?token=<jwt_token>
    """
    token = query_params.get("token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. No token provided in query parameter",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return token


def websocket_authenticate(websocket, verifier: CognitoJWTVerifier = None) -> TokenData:
    """
    Authenticate a WebSocket connection.
    Returns TokenData (Cognito claims) - developer handles DB lookup.

    Usage:
        @app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            try:
                token_data = websocket_authenticate(websocket)
                # then fetch your user from DB using token_data.sub
            except Exception as e:
                await websocket.close(code=4001, reason=str(e))
                return
    """
    if verifier is None:
        verifier = get_cognito_verifier()

    try:
        token = websocket.query_params.get("token")
        if not token:
            token = websocket.headers.get("Authorization")
            if token and token.startswith("Bearer "):
                token = token[7:]
        if not token:
            raise Exception("Missing authentication token for websocket.")

        token_data: TokenData = verifier.verify_token(token)
        return token_data

    except Exception as e:
        raise Exception(f"WebSocket authentication failed: {str(e)}")


async def get_current_user_ws(
    query_params: dict,
    verifier: CognitoJWTVerifier = None
) -> TokenData:
    """
    Get Cognito token claims from WebSocket connection.
    Token should be passed as query parameter: ?token=<jwt_token>

    Usage:
        @app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            query_params = dict(websocket.query_params)
            try:
                token_data = await get_current_user_ws(query_params)
                # fetch your user from DB using token_data.sub
            except HTTPException as e:
                await websocket.close(code=4001, reason=str(e.detail))
                return
    """
    if verifier is None:
        verifier = get_cognito_verifier()

    token = await get_token_from_query(query_params)
    token_data: TokenData = verifier.verify_token(token)
    return token_data