from sqlalchemy.orm import Session
from . import model, schemas
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/")
SECRET_KEY = "bdb8978186bb8efbe33c0e37109517b238a8acc0d8c16eeaaaa5273046497577"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_user(db: Session, user_id: int):
    return db.query(model.User).filter(model.User.id == user_id).first()


def get_user_by_email(db: Session, email: str):
    return db.query(model.User).filter(model.User.email == email).first()

def set_user_token(db: Session, email: str, token: str):
    user = db.query(model.User).filter(model.User.email == email).first()
    if user:
        user.token = token
        db.commit()
        
def get_user_token(db: Session, email: str):
    user = db.query(model.User).filter(model.User.email == email).first()
    if user:
        return user.token
    return None

def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(model.User).offset(skip).limit(limit).all()


def create_user(db: Session, user: schemas.UserCreate):
    fake_hashed_password = user.password
    db_user = model.User(email=user.email, hashed_password=fake_hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_hashed_password(password: str) -> str:
    return password_context.hash(password)

def verify_password(password: str, hashed_pass: str) -> bool:
    return password_context.verify(password, hashed_pass)