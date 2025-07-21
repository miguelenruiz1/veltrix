from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from src import db, models

# Configuración
SECRET_KEY = "veltrix-super-secret-key"
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")  # Este es el endpoint que genera token

# src/auth/dependencies.py

def get_current_user(token: str = Depends(oauth2_scheme), db_session: Session = Depends(db.get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token inválido o expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db_session.query(models.User).filter(models.User.id == int(user_id)).first()
    if not user:
        raise credentials_exception

    return user
