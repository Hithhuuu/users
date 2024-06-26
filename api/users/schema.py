"""Payload schema for user"""
from pydantic import BaseModel

class authentication(BaseModel):
    """payload detail for authentication api"""
    userid: str
    password : str

class createusers(BaseModel):
    """payload detail for craeting user"""
    encryptedData: str

class updateusers(BaseModel):
    """payload detail for updating user"""
    encryptedData: str

class deleteusers(BaseModel):
    """payload detail for deleting user"""
    userid :list[str]
