"""Application file for FAST API"""
import os
import sys
import uvicorn
import argparse
from dotenv import load_dotenv

parser = argparse.ArgumentParser()
parser.add_argument('-p','--port',type=int)
parser.add_argument('-e', '--env', type=str, default="dev")
args = parser.parse_args()
if os.getenv("ENV"):
    os.environ['env'] = args.env
dotenv = {
    "dev": "api/users/.env.dev",
}
load_dotenv(dotenv_path=dotenv.get(os.getenv("env")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from api.users.user_api import user_handler
from api.commons.fastapi_api import app
app.include_router(user_handler.router)
if __name__ == "__main__":
    if args.port:

        uvicorn.run(

            "user_server:app",

            host="0.0.0.0",

            port=args.port,

            workers=1,

            timeout_keep_alive=1,

        )
    else:
        print("Port number missing")