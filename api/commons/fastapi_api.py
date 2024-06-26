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
from api.commons.utils import get_async_connection_pool,get_logger


secret_key = (os.getenv("secret_key"))
auth_scheme = HTTPBearer()
app_log = get_logger("fastapi")
app = FastAPI()


@app.on_event("startup")
async def startup():
    try:
        app.state.pool = await get_async_connection_pool()
        app_log.info("starting the service")
        print("startup done")
    except Exception as e:
        print(e)



@app.on_event("shutdown")
async def shutdown():
    try:
        await app.state.pool.wait_closed()
        await app.state.pool.terminate()
        print("shutdown done")
    except Exception as e:
        print(e)



async def get_query_with_pool(query, resp_type="dict",data_list=None, executemany=False):
    """Run query using async"""
    app_log.debug(f"Query to be executed:\n{query}")
    start_time = datetime.datetime.now()
    try:
        async with app.state.pool.acquire() as con:
            if executemany:
                await con.executemany(query, data_list)
            if query.lower().startswith('insert') or query.lower().startswith('alter') or query.lower().startswith('update'):
                await con.execute(query)
                time_taken = datetime.datetime.now() - start_time
            elif resp_type not in ["None","none",None]:
                data = await con.fetch(query)
                time_taken = datetime.datetime.now() - start_time
                app_log.info(f"\nTime taken to run the query: {time_taken}")
                data_dicttype =  [dict(i)for i in data]
                if resp_type == "df":
                    data = pd.DataFrame(data, columns=data_dicttype[0].keys())
                elif resp_type == "dict":
                    data = data_dicttype
                elif resp_type == "length":
                    data = len(data)
                await app.state.pool.release(con)
                return data
            await app.state.pool.release(con)
    except Exception as err:
        await app.state.pool.release(con)
        print("Query Execution Failed:%s", str(err))
        raise err



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

        if not request.url.path.split("/")[-1] in ['auth', 'docs', 'openai']:
            jwt_token = request.headers.get("Authorization").split(" ")[1]
            payload = jwt.decode(jwt_token, secret_key, algorithms="HS256", options=options)
            url = str(request.url)
            if payload.get("env") != os.getenv("env"):
                return JSONResponse(content={"message": "Application Env Error "}, status_code=403)
            if not (bool(os.getenv("wvmpyenv") in url) ^ bool(url.split(os.getenv("wvmpyenv"))[-1].split('/')[1] not in payload.get("app_access").keys())):
                return JSONResponse(content={"message": "Forbidden App Access "}, status_code=403)
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
