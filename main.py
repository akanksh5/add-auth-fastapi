from typing import Annotated,Dict,Optional
from fastapi.encoders import jsonable_encoder
from fastapi import Depends, FastAPI, HTTPException, Query,Response, status,Request
from sqlmodel import Field, Session, SQLModel, create_engine, select
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import jwt 
from jwt import PyJWTError


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique = True)
    password: str | None = Field(default=None, index=True)


class UserPrompt(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    email: str = Field(index=True)
    prompt: str | None = Field(default=None, index=True)
    response: str | None = Field(default=None, index=True)


SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_WEEKS = 2
sqlite_file_name = "test.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"
connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, connect_args=connect_args)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(weeks=ACCESS_TOKEN_EXPIRE_WEEKS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print(payload)
        username: str = payload.get("email")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return username
    except PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session

SessionDep = Annotated[Session, Depends(get_session)]

app = FastAPI()

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

@app.post("/register")
def create_user(user: User, session: SessionDep) -> User:
    session.add(user)
    try:
        session.commit()
        session.refresh(user)
    except Exception as e:
        raise HTTPException(status_code=400, detail="user exists")
    return JSONResponse(status_code=201,content={"message": "user added successfully"})

@app.post("/login")
def get_user(response: Response,session: SessionDep,data: Dict):
    statement = select(User).where(User.email == data["email"] and User.password == data["password"])
    try:
        user = session.exec(statement).first()
        if not user:
           raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        access_token_expires = timedelta(weeks=ACCESS_TOKEN_EXPIRE_WEEKS)
        access_token = create_access_token(data={"email": user.email}, expires_delta=access_token_expires)
        response.set_cookie(
            key="session_token",            # Name of the cookie
            value=access_token,             # Value of the cookie
            httponly=True,                  # Set the cookie as HTTP-only
            max_age=3600,                   # Expiration time in seconds (1 hour)
            expires=3600,                   # Same as max_age
            secure=True,                    # Set True if using HTTPS
            samesite="lax"
        )
    except Exception:
        raise HTTPException(status_code=400, detail="invalid user id")


@app.post("/user_prompt")
def create_user_prompt(request:Request,user_prompt: UserPrompt, session: SessionDep) -> UserPrompt:
    cookies = request.cookies
    session_token = cookies.get("session_token")
    email = decode_access_token(session_token)
    user_prompt.email = email
    session.add(user_prompt)
    try:
        session.commit()
        session.refresh(user_prompt)
    except Exception as e:
        raise HTTPException(status_code=400, detail=e)
    return user_prompt

@app.post("/prompts")
def get_user_prompt(request:Request,session: SessionDep,data: Dict):
    cookies = request.cookies
    session_token = cookies.get("session_token")
    email = decode_access_token(session_token)
    statement = select(UserPrompt.prompt,UserPrompt.response).where(UserPrompt.email == email)
    try:
       users = session.exec(statement).all()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid user id")
    return [{"prompt": user.prompt, "response": user.response} for user in users]




