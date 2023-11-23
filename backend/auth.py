from jose import JWTError, jwt
from typing import Optional
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException
from fastapi.encoders import jsonable_encoder  # Import jsonable_encoder

SECRET_KEY = "bdb8978186bb8efbe33c0e37109517b238a8acc0d8c16eeaaaa5273046497577"
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/")

def create_jwt_token(user: dict) -> str:
    user_dict = jsonable_encoder(user)
    to_encode = user_dict.copy()
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str = Depends(oauth2_scheme)) -> Optional[dict]:
    credentials_exception = HTTPException(
        status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise credentials_exception
