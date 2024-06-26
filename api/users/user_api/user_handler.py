"""Handler for user API's"""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from api.user.schema import (authentication,createusers,updateusers,deleteusers)
from api.user.user_api.user_model import Users
from api.commons.utils import get_user

router = APIRouter(prefix="/user")


@router.get("") 
async def get():
    """On get request return the user\'s list as JSON"""
    user = Users()
    response = await user.get()
    if response.get("status", "success") != "error":
        return JSONResponse(response)
    return JSONResponse(
        status_code=response.get("status_code"),
        content={"message": response.get("content")},
    )

@router.post("/auth") 
async def auth(body: authentication):
    """On get request return the user\'s list as JSON"""
    user = Users()
    body=jsonable_encoder(body)
    response = await user.auth(body)
    if response.get("status", "success") != "error":
        return JSONResponse(response)
    return JSONResponse(
        status_code=response.get("status_code"),
        content={"message": response.get("content")},
    )

@router.post("") 
async def post(body:createusers):
    """On post request create the user if doesn't exist"""
    user = Users()
    body=jsonable_encoder(body)
    response = await user.create(body)
    if response.get("status_code") == 403 :
        return JSONResponse(
            status_code=response.get("status_code",403),
            content={"message": response.get("msg")},
        )
    return JSONResponse(content=response)


@router.put("")
async def put(body:updateusers):
    """On get request return the user\'s list as JSON"""
    user = Users()
    body=jsonable_encoder(body)
    response = await user.update(body)
    if response.get("status_code") or 'Current password' in response.get("msg"):
        return JSONResponse(
            status_code=response.get("status_code",400),
            content={"message": response.get("msg")},
        )
    return JSONResponse(content=response)


@router.delete("") #done
async def delete(request : Request ,body:deleteusers):
    """On get request return the user\'s list as JSON"""
    user = Users()
    body=jsonable_encoder(body)
    user_details = get_user(request)
    if user_details.get("userid") is not 'superadmin':
        return JSONResponse(
            status_code=401,
            content={"message": "Token not found"},
        )
    else :
        response = await user.delete(body)
        if response.get("status", "success") != "error":
            return JSONResponse(response)
        return JSONResponse(
            status_code=response.get("status_code"),
            content={"message": response.get("content")},
        )
