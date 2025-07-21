from fastapi import APIRouter, Depends, HTTPException, status, Body, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from jose import JWTError, jwt
import secrets, hashlib
from src.auth.dependencies import get_current_user


from .. import models, schemas, db, utils

router = APIRouter(prefix="/auth", tags=["auth"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")
SECRET_KEY = "veltrix-super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@router.post("/register", response_model=schemas.UserOut)
def register(user: schemas.UserRegister, db_session: Session = Depends(db.get_db)):
    existing = db_session.query(models.User).filter(models.User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed = utils.hash_password(user.password)
    new_user = models.User(email=user.email, hashed_password=hashed)
    db_session.add(new_user)
    db_session.commit()
    db_session.refresh(new_user)
    return new_user


@router.post("/token")
def login(credentials: dict = Body(...), db_session: Session = Depends(db.get_db)):
    email = credentials.get("email")
    password = credentials.get("password")
    
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password are required")

    user = db_session.query(models.User).filter(models.User.email == email).first()
    if not user or not utils.verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me", response_model=schemas.UserOut)
def read_users_me(current_user: models.User = Depends(get_current_user)):
    return current_user


@router.post("/logout")
def logout(request: Request):
    return {"message": "Logout successful. Please delete the token on the client side."}


@router.post("/refresh")
def refresh_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        
        new_token = create_access_token(data={"sub": email})
        return {"access_token": new_token, "token_type": "bearer"}

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


@router.post("/check")
def check_token(current_user: models.User = Depends(get_current_user)):
    return {
        "valid": True,
        "email": current_user.email,
        "user_id": current_user.id,
    }


@router.post("/forgot")
def forgot_password(data: dict = Body(...), db_session: Session = Depends(db.get_db)):
    email = data.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")
    
    user = db_session.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    raw_token = secrets.token_urlsafe(32)
    hashed_token = hashlib.sha256(raw_token.encode()).hexdigest()
    user.reset_token = hashed_token
    db_session.commit()

    print(f"[🔐 Recovery Email Simulado] http://localhost:8001/reset-password?token={raw_token}")
    return {"message": "Recovery link sent (check console/logs)"}


@router.post("/reset")
def reset_password(data: dict = Body(...), db_session: Session = Depends(db.get_db)):
    token = data.get("token")
    new_password = data.get("new_password")

    if not token or not new_password:
        raise HTTPException(status_code=400, detail="Token and new password are required")

    hashed_token = hashlib.sha256(token.encode()).hexdigest()
    user = db_session.query(models.User).filter(models.User.reset_token == hashed_token).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user.hashed_password = utils.hash_password(new_password)
    user.reset_token = None
    db_session.commit()
    return {"message": "Password reset successful"}
