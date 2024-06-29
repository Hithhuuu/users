"""Application file for FAST API"""
import os
import sys
import uvicorn
import argparse
from dotenv import load_dotenv
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

parser = argparse.ArgumentParser()
parser.add_argument('-p','--port',type=int)
parser.add_argument('-e', '--env', type=str, default="dev")
args = parser.parse_args()
if os.getenv("ENV"):
    os.environ['env'] = args.env
dotenv = {
    "dev": "api/user/.env.dev",
}
load_dotenv(dotenv_path=dotenv.get(os.getenv("env")))
from api.user.user_api import userhandler
from api.commons.fastapi_app import app
app.include_router(userhandler.router)
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