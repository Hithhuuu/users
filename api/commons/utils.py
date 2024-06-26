"""Utils file for WIzer"""
import os
import base64
import logging
import uuid
import socket
import yaml
import logging
from jwt import decode
from glob import glob
from hashlib import md5
from contextvars import ContextVar
from asynch import pool as pool_async
from Crypto import Random
from Crypto.Cipher import AES
from logging.handlers import TimedRotatingFileHandler


FORMATTER = logging.Formatter(
    "%(asctime)s — %(name)s — %(levelname)s — %(lineno)d — %(funcName)s — %(message)s"
)

def unpad(data):
    """doing unpaddling"""
    return data[: -(data[-1] if type(data[-1]) == int else ord(data[-1]))]


def bytes_to_key(data, salt, output=48):
    """creates key_iv"""
    assert len(salt) == 8, len(salt)
    data += salt
    key = md5(data).digest()
    final_key = key
    while len(final_key) < output:
        key = md5(key + data).digest()
        final_key += key
    return final_key[:output]


def pad(data):
    """adds padding"""
    bs = 16
    return data + (bs - len(data) % bs) * chr(bs - len(data) % bs)




def encrypt(password, key):
    """Encrypts password"""
    data = pad(password)
    salt = Random.new().read(8)
    key_iv = bytes_to_key(key, salt, 32 + 16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(b"Salted__" + salt + aes.encrypt(bytes(data, "utf-8")))


def decrypt(encrypted, passphrase):
    """Decrypts password"""
    encrypted = base64.b64decode(encrypted)
    assert encrypted[0:8] == b"Salted__"
    salt = encrypted[8:16]
    key_iv = bytes_to_key(passphrase, salt, 32 + 16)
    key = key_iv[:32]
    iv = key_iv[32:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return unpad(aes.decrypt(encrypted[16:]))

def get_queries(apiname =None):
    """Get api queries"""
    path = os.path.abspath(os.getcwd())
    query_files = glob(path + f"/api/{apiname}/queries/*.yaml", recursive=True) \
          if apiname else glob(path + "/api/*/*/*.yaml", recursive=True)
    queries = {}
    for qfile in query_files:
        key = os.path.splitext(os.path.basename(qfile))[0]
        with open(qfile) as file:
            queries[key] = yaml.load(file, Loader=yaml.SafeLoader)
            file.close()
    return queries


def get_user(request):
    """Get auth data"""
    auth = request.headers.get("Authorization")
    options = {
        "verify_signature": True,
        "verify_exp": True,
        "verify_nbf": False,
        "verify_iat": True,
        "verify_aud": False,
    }
    token = auth.split()[1]
    return decode(token, os.getenv("secret_key") \
            if os.getenv("secret_key") \
            else os.getenv("SECRET_KEY"),
            options=options, algorithms=["HS256"])



def get_console_handler():
    """Get console handler for logs"""
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(FORMATTER)
    return console_handler


def get_file_handler(log_file):
    """Get file handler for logs"""
    env = {
        "dev": 3,
        "demo": 3,
        "prd": 10
    }
    file_handler = TimedRotatingFileHandler(log_file, when="midnight", backupCount=env.get(os.getenv("tlfpyenv")))
    file_handler.setFormatter(FORMATTER)
    return file_handler


async def get_async_connection_pool():
    """
    Get an asynchronous connection pool.

    Returns:
        pool_async.Pool: An asynchronous connection pool.
    """
    return await pool_async.create_pool(
        dsn=os.getenv("DB_DSN"),
        port=5432,
        user=decrypt(os.getenv("db_user"),\
                      bytes(os.getenv("password_secret_key"), "utf-8")).decode("utf-8"),
        password=decrypt(os.getenv("db_password"), bytes(
            os.getenv("password_secret_key"), "utf-8")).decode("utf-8")
    )


def get_logger(logger_name):
    """
    Creates a logger for the api's
    param: logger name
    return: logger object
    """
    create_directories()
    logger = logging.getLogger(logger_name)
    # better to have too much log than not enough
    logger.setLevel(logging.DEBUG)
    # add new handlers for the logger
    logger.addHandler(get_console_handler())
    logger.addHandler(get_file_handler(f"logs/{logger_name}.log"))
    # with this pattern, it's rarely necessary to propagate the error up to parent
    logger.propagate = False
    return logger

def create_directories():
    """Initialize all required directories"""
    for d in os.getenv("directories"):
        if not (os.path.isdir(d)):
            os.mkdir(d)
    return True

queries = get_queries()

