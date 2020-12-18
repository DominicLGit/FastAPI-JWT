from typing import Optional

from fastapi.openapi.models import OAuthFlows
from fastapi.security.utils import get_authorization_scheme_param
from fastapi.templating import Jinja2Templates
import uvicorn
from passlib.context import CryptContext
from fastapi import Depends, FastAPI, HTTPException, status, Request, Form
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, OAuth2, HTTPBearer, HTTPBasicCredentials, \
    HTTPAuthorizationCredentials
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi.middleware.cors import CORSMiddleware
import requests
import ast

from starlette.responses import Response
from starlette.status import HTTP_403_FORBIDDEN

origins = [
    "http://localhost:8000",
    "http://localhost:8001",
    "http://localtest.me/",
    "http://localtest.me:8000",
    "http://127.0.0.1:8001/",
    "http://127.0.0.1:8000/",
    "http://server1.localtest.me:8000",
    "http://server2.localtest.me:8001/",
]

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


bearer_auth = HTTPBearer()

SECRET_KEY = "586E3272357538782F413F4428472B4B6250655368566D597033733676397924"
ALGORITHM = "HS256"


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_auth)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return User(username=username)


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(current_user: User = Depends(get_current_user)):
    return [{"item_id": "Foo", "owner": current_user.username}]


if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=8001)