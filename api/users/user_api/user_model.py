"""Model for user API"""
import os
import json
import traceback
import bcrypt
import requests

from datetime import datetime, timedelta, timezone
from jwt import encode
from api.commons.utils import   decrypt, encrypt, get_logger

app_log = get_logger("user")
env_config =[]

class Users:
    """User class for model"""


    async def auth(self, data):
        """Authentication users with username and password"""
        try:
            user = json.loads(os.getenv("users"))
            pass_word = decrypt(
                data["password"], bytes(
                    os.getenv("password_secret_key"), "utf-8")
            ).decode("utf-8")
            saved_password = decrypt(
                user["password"], bytes(
                    os.getenv("password_secret_key"), "utf-8")
            ).decode("utf-8")
            if  pass_word==saved_password and user.get("userid")==data.get("userid"):
                to_encode = {
                    "some": "payload",
                    "userid": data["userid"],
                    "a": {2: True},
                    "exp": datetime.utcnow() + timedelta(minutes=480),
                }
                encoded = encode(
                    to_encode, env_config["secret_key"], algorithm="HS256")
                jwt_key = (
                    encoded.decode(
                        "utf-8") if (isinstance(encoded, bytes)) else encoded
                )
                response_data = {
                    "jwt": jwt_key,
                    "expiredAt": str(to_encode["exp"]),
                }
                 
                return response_data

            return {
                "status": "error",
                "status_code": 401,
                "content": "Authentication failed",
            }
        except Exception as e:
            app_log.exception(e)
            return {
                "status": "error",
                "status_code": 500,
                "content": "Something went wrong",
            }



    async def navdetails(self, data) :
        """this method provides detials for nav"""
        try:
            query_param_str= '?Scheme_Type=Open'
            for i , k in data.items():
                if i.lower() in ["mutual_fund_family","scheme_type", "scheme_category" , "scheme_code", ]:
                    query_param_str+= f'{i}={k}'

            headers = {
                "x-rapidapi-key": "2e0499e573mshb8fd8d955b5f7bap1771a7jsnc8e15bb47f9b",
                "x-rapidapi-host": "latest-mutual-fund-nav.p.rapidapi.com"
            }

            response = requests.get(os.getenv("url"), headers=headers, params=querystring)
            if response.status_code ==200:
                return response.json()
            return {'msg': 'navdetails rapid api failed'}
        except Exception as e :
            app_log.exception(e)
            return {'msg': 'navdetails api failed'}