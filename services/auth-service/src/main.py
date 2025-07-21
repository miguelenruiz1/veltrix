from fastapi import FastAPI
from . import models, db
from .routes import auth, permissions

app = FastAPI()

models.Base.metadata.create_all(bind=db.engine)

app.include_router(auth.router)
app.include_router(permissions.router, prefix="/permissions")
