from typing import Optional
from fastapi.templating import Jinja2Templates
import uvicorn
from passlib.context import CryptContext
from fastapi import Depends, FastAPI, HTTPException, status, Request, Form
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi.middleware.cors import CORSMiddleware
import requests
import ast

origins = [
    "http://localhost:8000",
    "http://localhost:8001",
]

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


SECRET_KEY = "586E3272357538782F413F4428472B4B6250655368566D597033733676397924"
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


class TokenData(BaseModel):
    username: Optional[str] = None


@app.post("/token")
async def login_for_access_token(username: str = Form(...), password: str = Form(...)):
    token = requests.post('http://localhost:8000/token', data={'username': username, "password": password})
    return ast.literal_eval(token.text)


async def get_current_user(token: str):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    return User(username=token_data.username)


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user



@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": "Foo", "owner": current_user.username}]

templates = Jinja2Templates(directory="html")


@app.get("/")
async def main_page(request: Request):
    return templates.TemplateResponse("accept_jwt.html", {"request": request})

if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=8001)