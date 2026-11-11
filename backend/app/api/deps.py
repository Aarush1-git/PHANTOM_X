import uuid
import jwt
from typing import Optional, AsyncGenerator
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.database.session import get_db
from app.models.user import User
from shared.enums.common import UserRole

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/token",
    auto_error=False
)


async def get_current_user_optional(
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    if not token:
        return None
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        user_id = payload.get("sub")
        if user_id is None:
            return None
    except Exception:
        return None

    try:
        user_uuid = uuid.UUID(str(user_id))
        result = await db.execute(select(User).where(User.id == user_uuid))
        user = result.scalars().first()
        return user
    except Exception:
        return None


async def get_audit_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """
    Enforces authentication for audit log and security intelligence endpoints.
    In production environments (or when ALLOW_DEV_ANONYMOUS_AUDIT is False),
    an authenticated user is strictly required; missing or invalid tokens return 401.
    A local-development bypass is active ONLY when ENVIRONMENT == 'development' AND
    ALLOW_DEV_ANONYMOUS_AUDIT is explicitly True.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required: Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    is_dev_override_allowed = (
        settings.ENVIRONMENT == "development" and
        getattr(settings, "ALLOW_DEV_ANONYMOUS_AUDIT", False) is True
    )

    if not token:
        if is_dev_override_allowed:
            return None
        raise credentials_exception

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except Exception:
        raise credentials_exception

    try:
        user_uuid = uuid.UUID(str(user_id))
        result = await db.execute(select(User).where(User.id == user_uuid))
        user = result.scalars().first()
        if user is None or not user.is_active:
            raise credentials_exception
        return user
    except ValueError:
        raise credentials_exception


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception

    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except Exception:
        raise credentials_exception

    try:
        user_uuid = uuid.UUID(str(user_id))
        result = await db.execute(select(User).where(User.id == user_uuid))
        user = result.scalars().first()
        if user is None or not user.is_active:
            raise credentials_exception
        return user
    except ValueError:
        raise credentials_exception


def require_role(*allowed_roles: UserRole):
    """Enforce role-based access control on endpoints."""
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles and current_user.role != UserRole.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted with current role privileges"
            )
        return current_user
    return role_checker
