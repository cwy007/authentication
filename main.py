from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import select

from database import SessionDep, create_db_and_tables
from models import User, UserCreate, UserResponse, UserUpdate
from security import (
    DUMMY_HASH,
    create_access_token,
    create_refresh_token,
    decode_access_token,
    hash_password,
    verify_password,
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield


app = FastAPI(lifespan=lifespan)


def get_current_user(
    session: SessionDep,
    token: Annotated[str, Depends(oauth2_scheme)],
):
    invalid_token_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = decode_access_token(token)
    if not payload or payload.get("type") != "access":
        raise invalid_token_exception
    user = session.exec(select(User).where(User.email == payload.get("sub"))).first()
    if not user:
        raise invalid_token_exception
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


@app.post("/register", status_code=status.HTTP_201_CREATED, response_model=UserResponse)
def register(session: SessionDep, user_data: UserCreate):
    existing_user = session.exec(
        select(User).where(User.email == user_data.email)
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered"
        )

    new_user = User(
        email=user_data.email, hashed_password=hash_password(user_data.password)
    )
    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    return new_user


@app.post("/token", status_code=status.HTTP_200_OK)
def login(
    session: SessionDep, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = session.exec(select(User).where(User.email == form_data.username)).first()
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not user:
        verify_password(form_data.password, DUMMY_HASH)
        raise credential_exception

    if not verify_password(form_data.password, user.hashed_password):
        raise credential_exception

    return {
        "access_token": create_access_token({"sub": user.email}),
        "refresh_token": create_refresh_token({"sub": user.email}),
        "token_type": "bearer",
    }


user_router = APIRouter(dependencies=[Depends(get_current_user)], tags=["users"])


@user_router.get("/me", status_code=status.HTTP_200_OK, response_model=UserResponse)
def read_current_user(current_user: CurrentUser):
    return current_user


@user_router.patch("/me", status_code=status.HTTP_200_OK, response_model=UserResponse)
def update_current_user(
    session: SessionDep, current_user: CurrentUser, update_payload: UserUpdate
):
    if not update_payload.email:
        return current_user

    existing_user = session.exec(
        select(User).where(User.email == update_payload.email)
    ).first()
    if existing_user and existing_user.id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already taken",
        )
    current_user.email = update_payload.email

    session.add(current_user)
    session.commit()
    session.refresh(current_user)

    return current_user


@user_router.get("/dashboard", status_code=status.HTTP_200_OK)
def read_dashboard():
    return {"message": f"Welcome to your dashboard"}


app.include_router(user_router)
