from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from pymongo import MongoClient
from fastapi.security import OAuth2PasswordBearer

# ---------------- CONFIG ----------------
SECRET_KEY = "SUPER_SECRET_KEY_123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# ---------------- APP ----------------
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------------- DATABASE ----------------
client = MongoClient("mongodb://localhost:27017")
db = client["smart_analyzer"]
users_collection = db["users"]

# ---------------- MODELS ----------------
class UserRegister(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

# ---------------- HELPERS ----------------
def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(password, hashed):
    return pwd_context.verify(password, hashed)

def create_token(email: str):
    payload = {
        "sub": email,
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401)
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ---------------- ROUTES ----------------
@app.post("/signup")
def signup(data: UserRegister):
    if users_collection.find_one({"email": data.email}):
        raise HTTPException(status_code=400, detail="User already exists")

    users_collection.insert_one({
        "email": data.email,
        "hashed_password": hash_password(data.password),
        "created_at": datetime.utcnow()
    })

    return {"message": "User registered successfully"}

@app.post("/login")
def login(data: UserLogin):
    user = users_collection.find_one({"email": data.email})
    if not user or not verify_password(data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token(data.email)
    return {"access_token": token, "token_type": "bearer"}

@app.get("/protected")
def protected_route(current_user: str = Depends(get_current_user)):
    return {
        "message": "Access granted",
        "user": current_user
    }
