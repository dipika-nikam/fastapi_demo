from pydantic import BaseModel



class UserBase(BaseModel):
    email: str


class UserCreate(UserBase):
    password: str
