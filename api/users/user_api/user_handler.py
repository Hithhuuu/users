"""Handler for user API's"""
from fastapi import APIRouter, Request,Depends
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from api.user.schema import authentication
from api.user.user_api.user_model import Users
from api.commons.utils import get_user, verify_user

router = APIRouter()


@router.post("/auth") 
async def auth(body: authentication):
    """On get request return the user\'s list as JSON"""
    user = Users()
    response = await user.get()
    if response.get("status", "success") != "error":
        return JSONResponse(response)
    return JSONResponse(
        status_code=response.get("status_code"),
        content={"message": response.get("content")},
    )


@router.get("/navdetails") 
async def get(request: Request):
    """On get request return the user\'s list as JSON"""
    user = Users()
    query_params_dict = dict(request.query_params)
    response = await user.navdetails(query_params_dict)
    if response.get("status", "success") != "error":
        return JSONResponse(response)
    return JSONResponse(
        status_code=response.get("status_code"),
        content={"message": response.get("content")},
    )