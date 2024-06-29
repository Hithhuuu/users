"""Fast api setup for application"""
import time
import os
import itertools
import datetime
import pandas as pd
import jwt
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi import HTTPException,  Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from api.commons.utils import get_logger


secret_key = (os.getenv("secret_key"))
auth_scheme = HTTPBearer()
app_log = get_logger("fastapi")
app = FastAPI()


@app.middleware("http")
async def verify_jwt(request: Request, call_next):
    """
    Verify the JWT token in the request header and check for app access permissions.

    Args:
        request (Request): The incoming request object.
        call_next (Callable): The next middleware or route handler.

    Returns:
        JSONResponse: The response containing the result of the verification.

    Raises:
        jwt.exceptions.ExpiredSignatureError: If the JWT token has expired.
        jwt.exceptions.DecodeError: If there is an error decoding the JWT token.
        jwt.exceptions.InvalidTokenError: If the JWT token is invalid.
    """
    try:
        options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": False,
            "verify_iat": True,
            "verify_aud": False,
        }
        if 'auth' not in str(request.url):
            jwt_token = request.headers.get("Authorization").split(" ")[1]
            jwt.decode(jwt_token, secret_key, algorithms="HS256", options=options)
        return await call_next(request)
    except (
        jwt.exceptions.ExpiredSignatureError,
        jwt.exceptions.DecodeError,
        jwt.exceptions.InvalidTokenError,
    ):
        return JSONResponse(content={"message": "Invalid header authorization"}, status_code=401)

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """
    Middleware function to add a 'X-Process-Time' header to the response, indicating the time taken to process the request.

    Args:
        request (Request): The incoming request object.
        call_next (Callable): The next middleware or endpoint to call.

    Returns:
        Response: The response object with the 'X-Process-Time' header added.
    """
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
