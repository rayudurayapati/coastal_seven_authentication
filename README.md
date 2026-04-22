# cognito-auth-sdk-python

AWS Cognito authentication SDK for FastAPI. Drop it into any project — no database required.

## Install

> **This is a private repository.** Direct install won't work without authentication.
> You need a GitHub Personal Access Token (PAT).

```bash
pip install git+https://<your_username>:<your_token>@github.com/rayudurayapati/coastal_seven_authentication.git
```

**How to generate a PAT (Classic token — recommended):**
1. Go to GitHub → Settings → Developer Settings → Personal Access Tokens → **Tokens (classic)**
2. Click **Generate new token (classic)**
3. Select scope: ✅ **`repo`** (check the full repo checkbox)
4. Copy the token and use it in the command above

**Example:**
```bash
pip install git+https://johndoe:ghp_xxxxxxxxxxxxxxxxxxxx@github.com/rayudurayapati/coastal_seven_authentication.git
```

## Setup

### 1. Cognito User Pool Configuration
You **MUST** configure your AWS Cognito User Pool to accept custom attributes, otherwise native signups will fail.

1. Go to AWS Console → Cognito → User Pools → Your Pool
2. Go to **Sign-up experience** tab
3. Under **Custom attributes**, click **Add custom attribute**
4. Add the following **two** attributes:
   - Name: `country_code` (Type: String, Mutable: Yes, Min: 0, Max: 2048)
   - Name: `contact_number` (Type: String, Mutable: Yes, Min: 0, Max: 2048)

*(Note: They will automatically be prefixed with `custom:` in AWS)*

### 2. Environment Variables

Add to your `.env`:

```env
AWS_REGION=us-east-1
COGNITO_USER_POOL_ID=your-user-pool-id
COGNITO_APP_CLIENT_ID=your-app-client-id
COGNITO_DOMAIN=your-domain.auth.us-east-1.amazoncognito.com
OAUTH_REDIRECT_URI=/auth/callback        # for social login only
```

## Usage

```python
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from cognito_auth_sdk import auth_router

app = FastAPI()
app.include_router(auth_router)
```
## Protecting Your Routes

Use the `get_current_user` dependency to protect your own endpoints. It verifies the JWT and returns `TokenData` (containing `sub` and `email`).

```python
from fastapi import APIRouter, Depends
from cognito_auth_sdk.dependencies import get_current_user
from cognito_auth_sdk.schemas import TokenData

router = APIRouter()

@router.get("/my-protected-route")
def get_protected_data(token_data: TokenData = Depends(get_current_user)):
    # The token is perfectly valid if we reach here.
    user_id = token_data.sub
    email = token_data.email
    
    # -> Lookup user in your own database here using user_id or email
    
    return {"message": "You are authenticated!", "user": email}
```

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/auth/native/signup` | Register with email & password. Returns `{ message, email }` |
| `POST` | `/api/v1/auth/native/signup-confirmed` | Register & auto-verify user (bypasses OTP). Returns full user details. |
| `POST` | `/api/v1/auth/native/confirm` | Verify email OTP. Returns full user details — **create your DB row here** |
| `POST` | `/api/v1/auth/native/login` | Login. Returns `{ access_token, refresh_token, user_sub, email }` |
| `POST` | `/api/v1/auth/native/forgot-password` | Send password reset OTP |
| `POST` | `/api/v1/auth/native/confirm-forgot-password` | Reset password with OTP |
| `POST` | `/api/v1/auth/native/resend-code` | Resend email verification OTP |
| `DELETE` | `/api/v1/auth/native/delete-user` | Permanently delete a user from Cognito |
| `POST` | `/api/v1/auth/login` | Social login (Google/Facebook). Returns tokens + user details — **create your DB row here** |
| `POST` | `/api/v1/auth/signup` | Social signup (Google/Facebook). Alias for `/login` (Cognito handles this). |
| `GET` | `/api/v1/auth/validate-token` | Validate `access_token`. Returns `{ valid, user_sub, email }` |

## Social Login (Google)

Social login uses the OAuth2 PKCE flow — your frontend handles the redirect, backend handles the token exchange.

**Flow:**
1. Frontend generates `code_verifier` + `code_challenge` (PKCE)
2. Redirect user to Cognito hosted UI:
   ```
   https://<COGNITO_DOMAIN>/oauth2/authorize?response_type=code&client_id=<CLIENT_ID>&redirect_uri=<REDIRECT_URI>&identity_provider=Google&scope=email openid profile&code_challenge=<CHALLENGE>&code_challenge_method=S256
   ```
3. After Google login, Cognito redirects to your `REDIRECT_URI` with `?code=ABC`
4. Frontend sends the code to your backend:
   ```json
   POST /api/v1/auth/login
   { "code": "ABC", "code_verifier": "your_verifier" }
   ```
5. Backend returns tokens + user details — **create your DB row here**

> **Note**: Add your `REDIRECT_URI` to **Allowed Callback URLs** in AWS Cognito App Client settings.

## Rules

- **Native users**: can signup, login, forgot/reset password
- **Social users**: can only use social login — forgot password is blocked
- **DB is yours**: SDK never touches your database. Use `user_sub` as the link between Cognito and your DB
