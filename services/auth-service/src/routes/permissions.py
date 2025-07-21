from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from .. import models, schemas, db
from src.auth.dependencies import get_current_user

# Ruteador principal del módulo de permisos y roles
router = APIRouter(tags=["Permissions"])

# ---------------------------------------
# Crear un nuevo rol en el sistema
# ---------------------------------------
@router.post("/roles/")
def create_role(
    role: schemas.RoleCreate,
    db_session: Session = Depends(db.get_db),
    user=Depends(get_current_user)
):
    db_role = models.Role(name=role.name)
    db_session.add(db_role)
    db_session.commit()
    db_session.refresh(db_role)
    return db_role

# ---------------------------------------
# Crear un nuevo permiso en el sistema
# ---------------------------------------
@router.post("/permissions/")
def create_permission(
    permission: schemas.PermissionCreate,
    db_session: Session = Depends(db.get_db),
    user=Depends(get_current_user)
):
    db_permission = models.Permission(name=permission.name)
    db_session.add(db_permission)
    db_session.commit()
    db_session.refresh(db_permission)
    return db_permission

# ---------------------------------------
# Asignar una lista de permisos a un rol
# ⚠️ Sobrescribe todos los permisos existentes
# ---------------------------------------
@router.post("/permissions/assign")
def assign_permissions_to_role(
    data: schemas.AssignPermissionsInput,
    db_session: Session = Depends(db.get_db),
    user=Depends(get_current_user)
):
    role = db_session.query(models.Role).filter(models.Role.id == data.role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    permissions = db_session.query(models.Permission).filter(models.Permission.id.in_(data.permission_ids)).all()
    role.permissions = permissions  # Asignación directa, borra anteriores
    db_session.commit()
    return {"message": "Permissions assigned successfully"}

# ---------------------------------------
# Obtener los permisos asignados a un rol específico
# ---------------------------------------
@router.get("/roles/{id}/permissions")
def get_permissions_of_role(
    id: int,
    db_session: Session = Depends(db.get_db)
):
    role = db_session.query(models.Role).filter(models.Role.id == id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    return [{"id": p.id, "name": p.name} for p in role.permissions]

# ---------------------------------------
# Asignar uno o más roles a un usuario (sin eliminar roles previos)
# ---------------------------------------
@router.post("/users/{id}/assign-roles")
def assign_roles_to_user(
    id: int,
    data: schemas.AssignRolesInput,
    db_session: Session = Depends(db.get_db),
    user=Depends(get_current_user)
):
    user = db_session.query(models.User).filter(models.User.id == id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    roles_to_add = db_session.query(models.Role).filter(models.Role.id.in_(data.role_ids)).all()
    if not roles_to_add:
        raise HTTPException(status_code=404, detail="No valid roles found")

    existing_role_ids = {r.id for r in user.roles}
    for role in roles_to_add:
        if role.id not in existing_role_ids:
            user.roles.append(role)

    db_session.commit()
    return {
        "message": f"Roles added to user '{user.email}'",
        "total_roles": [r.id for r in user.roles]
    }

# ---------------------------------------
# Obtener todos los permisos que tiene un usuario por sus roles
# ---------------------------------------
@router.get("/users/{id}/permissions")
def get_user_permissions(
    id: int,
    db_session: Session = Depends(db.get_db),
    user=Depends(get_current_user)
):
    user = db_session.query(models.User).filter(models.User.id == id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    permissions = set()
    for role in user.roles:
        for p in role.permissions:
            permissions.add((p.id, p.name))

    return [{"id": pid, "name": pname} for pid, pname in permissions]

# ---------------------------------------
# Eliminar un rol específico de un usuario (no borra todos)
# ---------------------------------------
@router.delete("/users/{user_id}/roles/{role_id}")
def remove_role_from_user(
    user_id: int,
    role_id: int,
    db_session: Session = Depends(db.get_db),
    user=Depends(get_current_user)
):
    db_user = db_session.query(models.User).filter(models.User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    role = db_session.query(models.Role).filter(models.Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    if role not in db_user.roles:
        raise HTTPException(status_code=400, detail="User does not have this role")

    db_user.roles.remove(role)
    db_session.commit()
    return {
        "message": f"Role '{role.name}' removed from user '{db_user.email}'"
    }

# ---------------------------------------
# Eliminar un permiso específico de un rol (no borra todos)
# ---------------------------------------
@router.delete("/roles/{role_id}/permissions/{permission_id}")
def remove_permission_from_role(
    role_id: int,
    permission_id: int,
    db_session: Session = Depends(db.get_db),
    user=Depends(get_current_user)
):
    role = db_session.query(models.Role).filter(models.Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    permission = db_session.query(models.Permission).filter(models.Permission.id == permission_id).first()
    if not permission:
        raise HTTPException(status_code=404, detail="Permission not found")

    if permission not in role.permissions:
        raise HTTPException(status_code=400, detail="Role does not have this permission")

    role.permissions.remove(permission)
    db_session.commit()
    return {
        "message": f"Permission '{permission.name}' removed from role '{role.name}'"
    }

# ---------------------------------------
# Eliminar un rol (solo si no está asignado a ningún usuario)
# ---------------------------------------
@router.delete("/roles/{role_id}")
def delete_role(
    role_id: int,
    db_session: Session = Depends(db.get_db),
    user=Depends(get_current_user)
):
    role = db_session.query(models.Role).filter(models.Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    if role.users:
        raise HTTPException(status_code=400, detail="Cannot delete role: it is assigned to one or more users")

    db_session.delete(role)
    db_session.commit()
    return {
        "message": f"Role '{role.name}' deleted successfully"
    }

# ---------------------------------------
# Eliminar un permiso (solo si no está asignado a ningún rol)
# ---------------------------------------
@router.delete("/{permission_id}")
def delete_permission(
    permission_id: int,
    db_session: Session = Depends(db.get_db),
    user=Depends(get_current_user)
):
    permission = db_session.query(models.Permission).filter(models.Permission.id == permission_id).first()
    if not permission:
        raise HTTPException(status_code=404, detail="Permission not found")

    if permission.roles:
        raise HTTPException(status_code=400, detail="Cannot delete permission: it is assigned to one or more roles")

    db_session.delete(permission)
    db_session.commit()
    return {"message": f"Permission '{permission.name}' deleted successfully"}


