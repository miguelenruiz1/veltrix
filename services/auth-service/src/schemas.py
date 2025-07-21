from pydantic import BaseModel, EmailStr
from pydantic import BaseModel
from typing import List


# ----------- Auth: Registro y Login -----------
class UserRegister(BaseModel):
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    email: str
    password: str


class UserOut(BaseModel):
    id: int
    email: EmailStr

    class Config:
        orm_mode = True


# ----------- Auth: Tokens (login / refresh) -----------
class TokenResponse(BaseModel):
    access_token: str
    token_type: str


# ----------- Auth: Check Token Response -----------
class TokenCheckResponse(BaseModel):
    valid: bool
    email: EmailStr
    user_id: int

# --------- Roles & Permissions ---------

class RoleCreate(BaseModel):
    name: str

class PermissionCreate(BaseModel):
    name: str

class AssignPermissionsInput(BaseModel):
    role_id: int
    permission_ids: List[int]

class AssignRolesInput(BaseModel):
    role_ids: List[int]
