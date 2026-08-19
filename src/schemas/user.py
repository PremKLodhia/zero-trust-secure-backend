from pydantic import BaseModel, EmailStr, ConfigDict
from typing import Optional
from datetime import datetime

class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: str = "analyst"

class UserCreate(UserBase):
    pass

class UserResponse(UserBase):
    id: str
    is_active: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)
