"""Payload schema for user"""
from pydantic import BaseModel

class authentication(BaseModel):
    """payload detail for authentication api"""
    userid: str
    password : str

