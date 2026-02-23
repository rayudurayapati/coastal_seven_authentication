"""
Example: Cognito Auth SDK Integration with FastAPI
"""

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from cognito_auth_sdk import auth_router

app = FastAPI(
    title="My App",
    description="FastAPI app using Cognito Auth SDK",
    version="1.0.0"
)

# Mount all auth routes — that's it, auth is done
app.include_router(auth_router)


@app.get("/")
async def root():
    return {"message": "API is running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


# ─────────────────────────────────────────────
# HOW DB CREATION WORKS (no SDK involvement)
# ─────────────────────────────────────────────
#
# NATIVE USERS:
#   1. POST /api/v1/auth/native/signup  → OTP sent, don't create DB row yet
#   2. POST /api/v1/auth/native/confirm → returns user_sub, email, first_name, last_name
#                                         ← CREATE YOUR DB ROW HERE
#   3. POST /api/v1/auth/native/login   → returns access_token, refresh_token, user_sub, email
#
# SOCIAL USERS (Google):
#   1. POST /api/v1/auth/login          → returns tokens + user_sub, email, first_name, last_name
#                                         ← CREATE OR FETCH YOUR DB ROW HERE
