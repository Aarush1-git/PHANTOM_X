import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.session import get_db
from app.core.security import create_access_token, verify_password, get_password_hash
from app.models.user import User, Organization
from app.api.deps import get_current_user
from shared.contracts.models import TokenResponse, UserResponse, UserLogin
from shared.enums.common import UserRole

router = APIRouter()


@router.post("/token", response_model=TokenResponse)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    """OAuth2 password grant endpoint for token retrieval."""
    result = await db.execute(select(User).where(User.email == form_data.username))
    user = result.scalars().first()

    # Development fallback: If no user exists yet in database, provide a mock dev access token
    if not user and form_data.username == "admin@phantom-x.local":
        fake_id = uuid.uuid4()
        fake_org = uuid.uuid4()
        token = create_access_token(subject=fake_id, role="ADMIN", org_id=fake_org)
        return TokenResponse(
            access_token=token,
            token_type="bearer",
            expires_in=86400,
            user_id=fake_id,
            email=form_data.username,
            role=UserRole.ADMIN,
        )

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(subject=user.id, role=user.role.value, org_id=user.organization_id)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=86400,
        user_id=user.id,
        email=user.email,
        role=user.role,
    )


@router.post("/login", response_model=TokenResponse)
async def login_direct(
    credentials: UserLogin,
    db: AsyncSession = Depends(get_db)
):
    """Direct JSON login endpoint."""
    result = await db.execute(select(User).where(User.email == credentials.email))
    user = result.scalars().first()

    # Development fallback
    if not user and credentials.email == "admin@phantom-x.local":
        fake_id = uuid.uuid4()
        fake_org = uuid.uuid4()
        token = create_access_token(subject=fake_id, role="ADMIN", org_id=fake_org)
        return TokenResponse(
            access_token=token,
            token_type="bearer",
            expires_in=86400,
            user_id=fake_id,
            email=credentials.email,
            role=UserRole.ADMIN,
        )

    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    token = create_access_token(subject=user.id, role=user.role.value, org_id=user.organization_id)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=86400,
        user_id=user.id,
        email=user.email,
        role=user.role,
    )


@router.get("/me", response_model=UserResponse)
async def read_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    """Get authenticated user profile."""
    return UserResponse(
        id=current_user.id,
        organization_id=current_user.organization_id,
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role,
        is_active=current_user.is_active,
        created_at=current_user.created_at,
    )

