To start host the application please follow these instructions
    1. Install python with 3.11.9 version 
    2. Install all the required python libraries using requirements.txt
    3. To Launch the FastAPI application set working directory ./
    4. Run command python api/users/user_server.py
    5. Request to /auth endpoint to obtain JWT bearer token, using the following credentials 
                    {
                        "userid": "superadmin",
                        "password": "U2FsdGVkX18qiRE5Pgd4Alsacoe1h04NtEOUIPYX+bU="
                    }
    6. Once JWT token is obtained, request to /navdetails endpoint with respective query params for fetching NAV price along with token 