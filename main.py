import os
import json
from fastapi import FastAPI, HTTPException, Depends, status, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey, DateTime, Boolean, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from datetime import datetime, timedelta
from typing import Optional
import jwt
from passlib.context import CryptContext
from dotenv import load_dotenv

# ─────────────────────────────────────────────
# ENV & CONFIG
# ─────────────────────────────────────────────
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "oxbridge-super-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 7
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise Exception("❌ DATABASE_URL is missing! Set it in Render Environment Variables.")

# Fix for Render PostgreSQL URLs (they sometimes start with postgres:// instead of postgresql://)
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# ─────────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────────
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ─────────────────────────────────────────────
# MODELS  (must be defined BEFORE create_all)
# ─────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_online = Column(Boolean, default=False)
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

    messages_sent = relationship(
        "Message", back_populates="sender", foreign_keys="Message.sender_id"
    )
    messages_received = relationship(
        "Message", back_populates="receiver", foreign_keys="Message.receiver_id"
    )


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=False)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    receiver_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_read = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    sender = relationship("User", back_populates="messages_sent", foreign_keys=[sender_id])
    receiver = relationship("User", back_populates="messages_received", foreign_keys=[receiver_id])


# Create all tables NOW (after models are defined)
try:
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables checked/created successfully")
except Exception as e:
    print(f"❌ Error creating tables: {e}")
    raise


# ─────────────────────────────────────────────
# PYDANTIC SCHEMAS
# ─────────────────────────────────────────────
class UserRegister(BaseModel):
    username: str
    email: str
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    is_online: bool
    last_seen: datetime
    created_at: datetime

    class Config:
        from_attributes = True

class MessageSend(BaseModel):
    content: str
    receiver_username: str

class MessageOut(BaseModel):
    id: int
    content: str
    sender: str
    receiver: str
    is_read: bool
    timestamp: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    username: str
    email: str
    user_id: int


# ─────────────────────────────────────────────
# AUTH UTILITIES
# ─────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise credentials_exception
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please log in again.",
        )
    except jwt.PyJWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise credentials_exception
    return user


# ─────────────────────────────────────────────
# WEBSOCKET MANAGER
# ─────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        # Maps username -> WebSocket
        self.active: dict[str, WebSocket] = {}

    async def connect(self, username: str, websocket: WebSocket):
        await websocket.accept()
        self.active[username] = websocket

    def disconnect(self, username: str):
        self.active.pop(username, None)

    async def send_to(self, username: str, data: dict):
        ws = self.active.get(username)
        if ws:
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                self.disconnect(username)

    async def broadcast(self, data: dict, exclude: str = None):
        for username, ws in list(self.active.items()):
            if username == exclude:
                continue
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                self.disconnect(username)

    def is_online(self, username: str) -> bool:
        return username in self.active

    def online_users(self) -> list[str]:
        return list(self.active.keys())


manager = ConnectionManager()


# ─────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────
app = FastAPI(title="OX-Bridge API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.get("/")
def home():
    return {
        "status": "online",
        "message": "OX-Bridge API is Live! 🚀",
        "version": "2.0.0",
        "features": ["auth", "messaging", "websockets", "presence", "notifications"],
    }


# ── AUTH ──────────────────────────────────────

@app.post("/register", response_model=dict, status_code=201)
def register_user(user: UserRegister, db: Session = Depends(get_db)):
    # Check username length
    if len(user.username.strip()) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(user.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    # Check for duplicates
    existing = db.query(User).filter(
        (User.username == user.username.strip()) | (User.email == user.email.strip().lower())
    ).first()
    if existing:
        if existing.username == user.username.strip():
            raise HTTPException(status_code=400, detail="Username already taken")
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = User(
        username=user.username.strip(),
        email=user.email.strip().lower(),
        hashed_password=get_password_hash(user.password),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    access_token = create_access_token(data={"sub": new_user.username})
    return {
        "msg": "Account created successfully! 🎉",
        "access_token": access_token,
        "token_type": "bearer",
        "username": new_user.username,
        "email": new_user.email,
        "user_id": new_user.id,
    }


@app.post("/token", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS),
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username,
        "email": user.email,
        "user_id": user.id,
    }


@app.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user


# ── USERS ─────────────────────────────────────

@app.get("/users")
def get_all_users(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    users = db.query(User).filter(User.id != current_user.id).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "is_online": manager.is_online(u.username),
            "last_seen": str(u.last_seen),
        }
        for u in users
    ]


@app.get("/users/online")
def get_online_users(current_user: User = Depends(get_current_user)):
    return {"online_users": manager.online_users()}


# ── MESSAGES ──────────────────────────────────

@app.post("/send-message")
async def send_message(
    msg: MessageSend,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    receiver = db.query(User).filter(User.username == msg.receiver_username).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found")
    if receiver.id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot message yourself")

    new_msg = Message(
        content=msg.content,
        sender_id=current_user.id,
        receiver_id=receiver.id,
    )
    db.add(new_msg)
    db.commit()
    db.refresh(new_msg)

    # Real-time notification via WebSocket
    notification = {
        "type": "new_message",
        "message_id": new_msg.id,
        "from": current_user.username,
        "content": msg.content,
        "timestamp": str(new_msg.timestamp),
    }
    await manager.send_to(receiver.username, notification)

    return {"msg": "Message sent ✅", "message_id": new_msg.id}


@app.get("/messages/{other_username}")
def get_messages(
    other_username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    other = db.query(User).filter(User.username == other_username).first()
    if not other:
        raise HTTPException(status_code=404, detail="User not found")

    msgs = (
        db.query(Message)
        .filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == other.id))
            | ((Message.sender_id == other.id) & (Message.receiver_id == current_user.id))
        )
        .order_by(Message.timestamp.asc())
        .all()
    )

    # Mark received messages as read
    for m in msgs:
        if m.receiver_id == current_user.id and not m.is_read:
            m.is_read = True
    db.commit()

    return [
        {
            "id": m.id,
            "content": m.content,
            "sender": m.sender.username,
            "receiver": m.receiver.username,
            "is_read": m.is_read,
            "timestamp": str(m.timestamp),
        }
        for m in msgs
    ]


@app.get("/unread-count")
def unread_count(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    count = (
        db.query(Message)
        .filter(Message.receiver_id == current_user.id, Message.is_read == False)
        .count()
    )
    return {"unread_messages": count}


@app.get("/unread-count/{sender_username}")
def unread_from_user(
    sender_username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    sender = db.query(User).filter(User.username == sender_username).first()
    if not sender:
        raise HTTPException(status_code=404, detail="User not found")
    count = (
        db.query(Message)
        .filter(
            Message.sender_id == sender.id,
            Message.receiver_id == current_user.id,
            Message.is_read == False,
        )
        .count()
    )
    return {"from": sender_username, "unread_messages": count}


@app.delete("/messages/{message_id}")
def delete_message(
    message_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    if msg.sender_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only delete your own messages")
    db.delete(msg)
    db.commit()
    return {"msg": "Message deleted ✅"}


# ── WEBSOCKET ─────────────────────────────────

@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str, db: Session = Depends(get_db)):
    # Authenticate via token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            await websocket.close(code=4001)
            return
    except jwt.PyJWTError:
        await websocket.close(code=4001)
        return

    user = db.query(User).filter(User.username == username).first()
    if not user:
        await websocket.close(code=4001)
        return

    # Connect
    await manager.connect(username, websocket)

    # Update DB presence
    user.is_online = True
    user.last_seen = datetime.utcnow()
    db.commit()

    # Notify everyone this user is online
    await manager.broadcast(
        {"type": "presence", "username": username, "status": "online"},
        exclude=username,
    )

    # Send pending unread count to user on connect
    unread = (
        db.query(Message)
        .filter(Message.receiver_id == user.id, Message.is_read == False)
        .count()
    )
    await manager.send_to(username, {"type": "unread_count", "count": unread})

    try:
        while True:
            # Keep connection alive; client can send pings
            data = await websocket.receive_text()
            try:
                parsed = json.loads(data)
                # Handle ping
                if parsed.get("type") == "ping":
                    await manager.send_to(username, {"type": "pong"})
            except Exception:
                pass
    except WebSocketDisconnect:
        manager.disconnect(username)
        # Update DB presence
        db2 = SessionLocal()
        try:
            u = db2.query(User).filter(User.username == username).first()
            if u:
                u.is_online = False
                u.last_seen = datetime.utcnow()
                db2.commit()
        finally:
            db2.close()
        # Notify everyone this user is offline
        await manager.broadcast(
            {"type": "presence", "username": username, "status": "offline"}
        )


# ── ADMIN (protected) ─────────────────────────

@app.delete("/admin/clear-all")
def clear_all(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Only allow if username is "admin"
    if current_user.username != "admin":
        raise HTTPException(status_code=403, detail="Admin access only")
    db.query(Message).delete()
    db.query(User).delete()
    db.commit()
    return {"msg": "All data cleared ✅"}
