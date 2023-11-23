from fastapi import Depends, FastAPI, HTTPException,status
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from . import form, model, schemas
from .database import SessionLocal, engine
from datetime import datetime, timedelta
from typing import Optional

model.Base.metadata.create_all(bind=engine)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login/")

app = FastAPI()

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"

def create_jwt_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/users/", response_model=dict)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = form.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    user.password = form.get_hashed_password(user.password)
    created_user = form.create_user(db=db, user=user)
    expires_delta = timedelta(minutes=15)
    access_token = create_jwt_token({"sub": created_user.email}, expires_delta)
    
    form.set_user_token(db, email=created_user.email, token=access_token)
    return {"data": {"email": created_user.email, "access_token": access_token, "token_type": "bearer"}}


@app.get("/api")
async def root():
    return {"message": "Awesome"}

@app.post('/verify_token')
async def verify_token_route(token: str):
    return verify_token(token)

@app.post('/login', summary="Create access token for user")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    db_user = form.get_user_by_email(db, email=form_data.username)
    if db_user is None or not form.verify_password(form_data.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    
    expires_delta = timedelta(minutes=15)
    access_token = create_jwt_token({"sub": db_user.email}, expires_delta)
    response = {"access_token": access_token, "token_type": "bearer"}
    return response