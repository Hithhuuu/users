"""Model for user API"""
import os
import json
import traceback
import bcrypt

from datetime import datetime, timedelta, timezone
from jwt import encode

from api.user.utils import queries,  decrypt, encrypt, smart_logger
from api.user.fastapi_app import get_query_with_pool

app_log = smart_logger("user")
env_config =[]

class Users:
    """User class for model"""

    def __init__(self):
        """Initializing queries for user API"""
        self.queries = queries["user"]

    async def get(self):
        '''Get list of users'''
        try:
            app_log.info('Get list of users')
            app_log.info(self.queries['read'])
            data = await get_query_with_pool(self.queries["read"],resp_type="dict")
            app_log.info(data)
            data1 = {'encryptedData': encrypt(f'{json.dumps(data)}',
                                               bytes(os.environ.get("password_secret_key")
                                                              , 'utf-8')).decode('ascii')}
            app_log.info(data1)
        except Exception as e:
            print(traceback.format_exc())
            app_log.error(e)
            return{'error': str(e)}
        return (data1)

    def get_password(self, password):
        """Decode the Users password"""
        salt = bcrypt.gensalt()
        password = bcrypt.hashpw(password.encode(), salt)
        return password.decode()

    async def create(self, data):
        '''creates new user'''
        try:
            app_log.info('Create user')
            data = json.loads(decrypt(data['encryptedData'],
                                       bytes(os.environ.get("password_secret_key"), 'utf-8')). \
                decode("utf-8"))
            user_exists_query = self.queries['user_exists'].format(**data)
            app_log.info(f'user EXISTS QUERY: {user_exists_query}')
            users = await get_query_with_pool(
                user_exists_query, "dict"
            )

            if len(users):
                return {"msg": "user exists"}

            pass_word = decrypt(
                data["password"], bytes(
                    os.environ.get("password_secret_key"), "utf-8")
            ).decode("utf-8")
            data["password"] = self.get_password(pass_word)
            app_access = await self.access_roles(data, operation_type="create")
            if not app_access:
                return {
                "msg": "User does not have access to create user for this app","status_code": 403}
            # Create new user
            data['app_access'] = app_access
            data["rfg"] = 1 if data.get("isactive") == "Y" else 2
            user_create_query = self.queries["create"].format(**data).replace("'","\'")
            await get_query_with_pool(user_create_query,resp_type="None")
        except Exception as err:
            app_log.error("Error while creating new user")
            app_log.exception(err)
            return {"error": str(err)}
        return {"msg": "user created"}

    async def prepare_query(self, data):
        """Prepare the query filter conditions"""
        query_data = {
            "userid": "userid",
            "firstname": "firstname",
            "lastname": "lastname",
            "email": "email",
            "uby" : "uby",
            "udt" : "now() ",
            "password": "password",
            "rfg": "rfg",
            "app_access": "app_access",
            "preferedname": "preferedname",
            "usertype": "usertype"
        }
        for key in data.keys():
            if key == "isactive":
                query_data["rfg"] = f"""{1 if data.get("isactive") == "Y" else 2} as rfg"""
            elif key == "userid":
                query_data[key] = f"{key} = '{data.get(key)}' "
            elif key == "app_access":
                app_str= [f"'{i}','{k}'"
                for i, k in data.get('app_access').items()
                ]
                query_data[key] = f"map({' ,'.join(app_str)}) as {key}"
            else:
                query_data[key] = f"'{data.get(key)}' as {key}"
        return query_data

    async def access_roles(self, data, operation_type='create'):
        """
        Retrieves the access roles for a user based on the provided data.

        Args:
            data (dict): The data containing the user information.
            operation_type (str, optional): The type of operation. Defaults to 'create'.

        Returns:
            dict: A dictionary containing the access roles for each application.
        """
        cby_query = self.queries['authenticate'].format(userid=data.get('cby') \
                                                        if operation_type == 'create' \
                                                                else data.get('uby'))
        cby_data= await get_query_with_pool(cby_query, resp_type='dict')
        user_query = self.queries['authenticate'].format(userid=data.get('userid'))
        user_data = await get_query_with_pool(user_query, resp_type='dict')
        app_access ={}
        for i, k in data.get('app_access').items():
            if i in cby_data[0].get('app_access').keys() \
                and cby_data[0].get('app_access').get(i) == 'admin':
                app_access[i] = k
            elif user_data and user_data[0].get('app_access'):
                app_access[i] = user_data[0].get('app_access').get(i)
        return app_access

    async def update(self, data):
        """Update user record"""
        try:
            app_log.info("Update User Record")
            data = json.loads(decrypt(data['encryptedData'],
                                       bytes(os.environ.get("password_secret_key"), 'utf-8')). \
                decode("utf-8"))

            user_auth_query = self.queries["authenticate_update"].format(
                **data)
            user_data = await get_query_with_pool(user_auth_query, resp_type='dict')
            if len(user_data) <= 0 or user_data[0]['rfg'] == 0:
                return {"msg": "UserID not valid"}
            # user_data = user_data[0]
            if data.get("currentPassword", "") != "":
                pass_word = decrypt(
                    data["currentPassword"],
                    bytes(os.environ.get("password_secret_key"), "utf-8"),
                ).decode("utf-8")
                # Verify user input password and user data password are equal or not
                if not bcrypt.checkpw(
                    pass_word.encode(), user_data[0]["password"].encode()
                ):
                    return {
                        "msg": f"Current password is incorrect for user {data['userid']}."
                    }
            if data.get("password") and data.get("userid")=='superadmin':
                pass_word = decrypt(
                    data["password"],
                    bytes(os.environ.get("password_secret_key"), "utf-8"),
                ).decode("utf-8")
                data["password"] = self.get_password(pass_word)
            data['app_access'] = await self.access_roles(data, operation_type = 'update')
            if len(set(data['app_access'].values()))<2  \
                and None in set(data['app_access'].values()) :
                return {
                "msg": "User does not have access to update user for this app","status_code": 403}
            query_data = await self.prepare_query(data)
            user_update_query = self.queries["update"].format(**query_data)
            await get_query_with_pool(user_update_query,resp_type=None)

        except Exception as err:
            app_log.error("Error while updating user record")
            app_log.exception(err)
            return {"error": str(err)}
        return {"msg": f"user {data['userid']} updated successfully"}

    async def delete(self, data):
        '''Delete user'''
        try:
            app_log.info('Delete users')
            data['userid'] = "', '".join(data['userid'])
            user_delete_query = self.queries['delete'].format(**data)
            app_log.info(f'user DELETE QUERY: {user_delete_query}')
            await get_query_with_pool(user_delete_query,resp_type=None)
            resp =  await self.get()
            return resp
        except Exception as e:
            app_log.error(e)
            return {"error": str(e)}

    async def data(self, data):
        ''' Get the user details for Authentication '''
        try:
            app_log.info('Authenticating users')
            user_auth_query = self.queries['authenticate'].format(**data)
            app_log.info(f"user AUTH QUERY: {user_auth_query}")
            user_data = await get_query_with_pool(user_auth_query, "dict")
        except Exception as e:
            app_log.error(e)
            return {'error': str(e)}
        return (user_data)

    async def auth(self, data):
        """Authentication users with username and password"""
        try:
            user_data = await self.data(data)
            if len(user_data) <= 0 or user_data[0]["rfg"] != 1:
                return {
                    "status": "error",
                    "status_code": 401,
                    "content": "userID not valid",
                }

            user_data = user_data[0]
            pass_word = decrypt(
                data["password"], bytes(
                    os.environ.get("password_secret_key"), "utf-8")
            ).decode("utf-8")

            if self.check_password(user_data["password"], pass_word):
                to_encode = {
                    "some": "payload",
                    "userid": data["userid"],
                    "exp": datetime.now(timezone.utc) + timedelta(minutes=480),
                    "app_access" : user_data["app_access"],
                    "env": os.environ.get("wvmpyenv")
                }
                encoded = encode(
                    to_encode, os.environ.get("secret_key"), algorithm="HS256")
                jwt_key = (
                    encoded.decode(
                        "utf-8") if (isinstance(encoded, bytes)) else encoded
                )
                response_data = {
                    "jwt": jwt_key,
                    "userid": user_data["userid"],
                    "username": user_data["email"],
                    "firstname": user_data["firstname"],
                    "displayName": user_data["firstname"] + " " + user_data["lastname"],
                    "expiredAt": str(to_encode["exp"]),
                    "app_access": user_data["app_access"],
                }
                response = {
                    "encryptedData": encrypt(
                        f"{response_data}".replace("'", '"'),
                        bytes(os.environ.get("password_secret_key"), "utf-8"),
                    ).decode("ascii")
                }
                app_log.info("Successfully authenticated")

                return response

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

    async def refresh(self, data):
        """
        Refreshes the user's authentication token.

        Args:
            data (dict): The user data containing the user ID.

        Returns:
            dict: The response containing the refreshed authentication token and user information.

        Raises:
            Exception: If an error occurs during the refresh process.
        """
        try:
            user_data = await self.data(data)
            if len(user_data) <= 0 or user_data[0]["rfg"] != 1:
                return {
                    "status": "error",
                    "status_code": 401,
                    "content": "UserID not valid",
                }
            user_data = user_data[0]
            to_encode = {
                "some": "payload",
                "userid": data["userid"],
                "a": {2: True},
                "exp": datetime.now(timezone.utc) + timedelta(minutes=480),
            }
            encoded = encode(to_encode, os.environ.get("secret_key"), algorithm="HS256")
            response = {
                "jwt": encoded.decode("utf-8"),
                "userid": user_data["userid"],
                "username": user_data["email"],
                "firstname": user_data["firstname"],
                "isadmin": "Y" if user_data["assignedrole"] == "admin" else "N",
                "displayName": f"{user_data['firstname']} {user_data['lastname']}",
                "expiredAt": to_encode["exp"],
            }
            response = {
                "encryptedData": encrypt(
                    f"{response}".replace("'", '"'),
                    bytes(os.environ.get("password_secret_key"), "utf-8"),
                ).decode("ascii")
            }
            return response
        except Exception as e:
            app_log.exception(e)
            return {
                "status": "error",
                "status_code": 500,
                "content": "Something went wrong",
            }

    def check_password(self, user_password, requested_password):
        """Check User password"""
        return bcrypt.checkpw(requested_password.encode(), user_password.encode())
