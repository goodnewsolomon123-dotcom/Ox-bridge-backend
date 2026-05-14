import os
import json
import secrets
import cloudinary
import cloudinary.uploader
from fastapi import (
    FastAPI, HTTPException, Depends, status,
    WebSocket, WebSocketDisconnect, UploadFile, File, Form, Header
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import (
    create_engine, Column, Integer, String, Text,
    ForeignKey, DateTime, Boolean, func, Table
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from datetime import datetime, timedelta
from typing import Optional, List
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
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "oxbridge-admin-2024")

if not DATABASE_URL:
    raise Exception("❌ DATABASE_URL is missing!")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Cloudinary config
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
)

# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ─────────────────────────────────────────────
# MODELS
# ─────────────────────────────────────────────

# Group members association table
group_members = Table(
    "group_members", Base.metadata,
    Column("group_id", Integer, ForeignKey("groups.id"), primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
)


class DeveloperApp(Base):
    """Represents a developer/app using the OX-Bridge API platform."""
    __tablename__ = "developer_apps"

    id = Column(Integer, primary_key=True, index=True)
    app_name = Column(String(100), unique=True, nullable=False)
    developer_email = Column(String(255), unique=True, nullable=False)
    api_key = Column(String(64), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    users = relationship("User", back_populates="app")
    groups = relationship("Group", back_populates="app")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), nullable=False)
    email = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    avatar_url = Column(String(500), nullable=True)
    is_online = Column(Boolean, default=False)
    is_banned = Column(Boolean, default=False)
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Each user belongs to one app — this is how isolation works
    app_id = Column(Integer, ForeignKey("developer_apps.id"), nullable=False)
    app = relationship("DeveloperApp", back_populates="users")

    messages_sent = relationship("Message", back_populates="sender", foreign_keys="Message.sender_id")
    messages_received = relationship("Message", back_populates="receiver", foreign_keys="Message.receiver_id")
    groups = relationship("Group", secondary=group_members, back_populates="members")
    group_messages = relationship("GroupMessage", back_populates="sender")


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=True)
    media_url = Column(String(500), nullable=True)
    media_type = Column(String(20), nullable=True)  # image | video | audio | file
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    receiver_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_read = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    sender = relationship("User", back_populates="messages_sent", foreign_keys=[sender_id])
    receiver = relationship("User", back_populates="messages_received", foreign_keys=[receiver_id])


class Group(Base):
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(String(255), nullable=True)
    avatar_url = Column(String(500), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    app_id = Column(Integer, ForeignKey("developer_apps.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    app = relationship("DeveloperApp", back_populates="groups")
    members = relationship("User", secondary=group_members, back_populates="groups")
    messages = relationship("GroupMessage", back_populates="group")


class GroupMessage(Base):
    __tablename__ = "group_messages"

    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=True)
    media_url = Column(String(500), nullable=True)
    media_type = Column(String(20), nullable=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    sender = relationship("User", back_populates="group_messages")
    group = relationship("Group", back_populates="messages")


# Create all tables
try:
    Base.metadata.create_all(bind=engine)
    print("✅ OX-Bridge v3.0 — Database tables ready")
except Exception as e:
    print(f"❌ Table creation error: {e}")
    raise


# ─────────────────────────────────────────────
# SCHEMAS
# ─────────────────────────────────────────────

class DevRegister(BaseModel):
    app_name: str
    developer_email: str
    password: str

class DevLogin(BaseModel):
    developer_email: str
    password: str

class UserRegister(BaseModel):
    username: str
    email: str
    password: str

class MessageSend(BaseModel):
    content: str
    receiver_username: str

class GroupCreate(BaseModel):
    name: str
    description: Optional[str] = None

class GroupMessageSend(BaseModel):
    content: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    username: str
    email: str
    user_id: int

class RTCSignal(BaseModel):
    to_username: str
    signal_type: str   # offer | answer | ice-candidate | call-request | call-end
    payload: dict


# ─────────────────────────────────────────────
# AUTH UTILITIES
# ─────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


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


def get_app_from_key(x_api_key: str = Header(...), db: Session = Depends(get_db)) -> DeveloperApp:
    """Validates X-API-Key header and returns the developer app."""
    app = db.query(DeveloperApp).filter(
        DeveloperApp.api_key == x_api_key,
        DeveloperApp.is_active == True
    ).first()
    if not app:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key")
    return app


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired. Please log in again.")
    except jwt.PyJWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise credentials_exception
    if user.is_banned:
        raise HTTPException(status_code=403, detail="Your account has been banned.")
    return user


def get_admin(admin_secret: str = Header(..., alias="X-Admin-Secret")):
    if admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Admin access denied")
    return True


# ─────────────────────────────────────────────
# WEBSOCKET MANAGER
# ─────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        # key: f"{app_id}:{username}" -> WebSocket
        self.active: dict[str, WebSocket] = {}

    def _key(self, app_id: int, username: str) -> str:
        return f"{app_id}:{username}"

    async def connect(self, app_id: int, username: str, websocket: WebSocket):
        await websocket.accept()
        self.active[self._key(app_id, username)] = websocket

    def disconnect(self, app_id: int, username: str):
        self.active.pop(self._key(app_id, username), None)

    async def send_to(self, app_id: int, username: str, data: dict):
        ws = self.active.get(self._key(app_id, username))
        if ws:
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                self.disconnect(app_id, username)

    async def broadcast_app(self, app_id: int, data: dict, exclude: str = None):
        prefix = f"{app_id}:"
        for key, ws in list(self.active.items()):
            if not key.startswith(prefix):
                continue
            username = key.split(":", 1)[1]
            if username == exclude:
                continue
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                self.active.pop(key, None)

    async def broadcast_group(self, app_id: int, member_usernames: list, data: dict, exclude: str = None):
        for username in member_usernames:
            if username == exclude:
                continue
            await self.send_to(app_id, username, data)

    def is_online(self, app_id: int, username: str) -> bool:
        return self._key(app_id, username) in self.active

    def online_in_app(self, app_id: int) -> list:
        prefix = f"{app_id}:"
        return [k.split(":", 1)[1] for k in self.active if k.startswith(prefix)]


manager = ConnectionManager()


# ─────────────────────────────────────────────
# CLOUDINARY UPLOAD HELPER
# ─────────────────────────────────────────────
ALLOWED_IMAGE = {"image/jpeg", "image/png", "image/gif", "image/webp"}
ALLOWED_VIDEO = {"video/mp4", "video/webm", "video/quicktime"}
ALLOWED_AUDIO = {"audio/mpeg", "audio/ogg", "audio/wav", "audio/webm", "audio/mp4"}
MAX_FILE_MB = 20


async def upload_media(file: UploadFile) -> dict:
    if file.content_type in ALLOWED_IMAGE:
        resource_type = "image"
        media_type = "image"
    elif file.content_type in ALLOWED_VIDEO:
        resource_type = "video"
        media_type = "video"
    elif file.content_type in ALLOWED_AUDIO:
        resource_type = "video"  # Cloudinary uses "video" for audio too
        media_type = "audio"
    else:
        resource_type = "raw"
        media_type = "file"

    contents = await file.read()
    if len(contents) > MAX_FILE_MB * 1024 * 1024:
        raise HTTPException(status_code=400, detail=f"File too large. Max {MAX_FILE_MB}MB.")

    result = cloudinary.uploader.upload(
        contents,
        resource_type=resource_type,
        folder="oxbridge",
    )
    return {"url": result["secure_url"], "media_type": media_type}


# ─────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────
app = FastAPI(
    title="OX-Bridge API Platform",
    version="3.0.0",
    description="""
## OX-Bridge — Backend as a Service

A powerful real-time messaging API platform.
Developers register their app, get an **API Key**, and use it to power their own chat apps.

### Features
- 🔑 Per-app user isolation (users from App A never mix with App B)
- 💬 Real-time messaging via WebSockets
- 📸 Media uploads (images, videos, voice) via Cloudinary
- 👥 Group chats
- 📞 Voice & Video call signaling (WebRTC)
- 🛡️ Admin dashboard

### Quick Start
1. `POST /developer/register` — Register your app, get an API key
2. Use `X-API-Key: your_key` header on all user endpoints
3. `POST /auth/register` — Register users under your app
4. Connect WebSocket at `/ws/{token}`
    """,
)

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

@app.get("/", tags=["General"])
def home():
    return {
        "status": "online",
        "name": "OX-Bridge API Platform",
        "version": "3.0.0",
        "docs": "/docs",
        "features": [
            "app-isolation", "auth", "real-time-messaging",
            "media-uploads", "group-chats", "webrtc-signaling",
            "presence", "admin-dashboard"
        ],
    }


# ── DB RESET (one-time use after schema changes) ───
@app.get("/admin/reset-db", tags=["Admin"])
def reset_db():
    try:
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        return {"msg": "✅ Database reset successfully! Register a new developer app to begin."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ══════════════════════════════════════════════
# DEVELOPER / APP MANAGEMENT
# ══════════════════════════════════════════════

@app.post("/developer/register", tags=["Developer"])
def register_developer(data: DevRegister, db: Session = Depends(get_db)):
    """Register a new developer app and receive your API key."""
    if len(data.app_name.strip()) < 3:
        raise HTTPException(status_code=400, detail="App name must be at least 3 characters")
    if len(data.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    existing = db.query(DeveloperApp).filter(
        (DeveloperApp.app_name == data.app_name.strip()) |
        (DeveloperApp.developer_email == data.developer_email.strip().lower())
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="App name or email already registered")

    api_key = secrets.token_hex(32)
    dev_app = DeveloperApp(
        app_name=data.app_name.strip(),
        developer_email=data.developer_email.strip().lower(),
        api_key=api_key,
        hashed_password=get_password_hash(data.password),
    )
    db.add(dev_app)
    db.commit()
    db.refresh(dev_app)

    return {
        "msg": "Developer app registered! 🎉",
        "app_name": dev_app.app_name,
        "api_key": api_key,
        "note": "Include X-API-Key header in all your app's requests. Keep this key secret!",
    }


@app.post("/developer/login", tags=["Developer"])
def developer_login(data: DevLogin, db: Session = Depends(get_db)):
    """Retrieve your API key by logging in."""
    dev = db.query(DeveloperApp).filter(
        DeveloperApp.developer_email == data.developer_email.strip().lower()
    ).first()
    if not dev or not verify_password(data.password, dev.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {
        "app_name": dev.app_name,
        "api_key": dev.api_key,
        "is_active": dev.is_active,
    }


@app.get("/developer/stats", tags=["Developer"])
def developer_stats(
    dev_app: DeveloperApp = Depends(get_app_from_key),
    db: Session = Depends(get_db)
):
    """Get stats for your app."""
    user_count = db.query(User).filter(User.app_id == dev_app.id).count()
    message_count = db.query(Message).join(User, Message.sender_id == User.id).filter(User.app_id == dev_app.id).count()
    group_count = db.query(Group).filter(Group.app_id == dev_app.id).count()
    online = manager.online_in_app(dev_app.id)
    return {
        "app_name": dev_app.app_name,
        "total_users": user_count,
        "total_messages": message_count,
        "total_groups": group_count,
        "online_now": len(online),
        "online_users": online,
    }


# ══════════════════════════════════════════════
# USER AUTH (scoped per app via API key)
# ══════════════════════════════════════════════

@app.post("/auth/register", status_code=201, tags=["Auth"])
def register_user(
    user: UserRegister,
    dev_app: DeveloperApp = Depends(get_app_from_key),
    db: Session = Depends(get_db)
):
    """Register a user under your app. Requires X-API-Key header."""
    if len(user.username.strip()) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(user.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    # Uniqueness is per-app only
    existing = db.query(User).filter(
        User.app_id == dev_app.id,
        (User.username == user.username.strip()) | (User.email == user.email.strip().lower())
    ).first()
    if existing:
        if existing.username == user.username.strip():
            raise HTTPException(status_code=400, detail="Username already taken in this app")
        raise HTTPException(status_code=400, detail="Email already registered in this app")

    new_user = User(
        username=user.username.strip(),
        email=user.email.strip().lower(),
        hashed_password=get_password_hash(user.password),
        app_id=dev_app.id,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = create_access_token(data={"sub": str(new_user.id), "app_id": dev_app.id})
    return {
        "msg": "Account created successfully! 🎉",
        "access_token": token,
        "token_type": "bearer",
        "username": new_user.username,
        "email": new_user.email,
        "user_id": new_user.id,
    }


@app.post("/auth/login", tags=["Auth"])
def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(),
    dev_app: DeveloperApp = Depends(get_app_from_key),
    db: Session = Depends(get_db)
):
    """Login a user. Requires X-API-Key header."""
    user = db.query(User).filter(
        User.app_id == dev_app.id,
        User.username == form_data.username
    ).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    if user.is_banned:
        raise HTTPException(status_code=403, detail="This account has been banned")

    token = create_access_token(
        data={"sub": str(user.id), "app_id": dev_app.id},
        expires_delta=timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username,
        "email": user.email,
        "user_id": user.id,
        "avatar_url": user.avatar_url,
    }


@app.get("/auth/me", tags=["Auth"])
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "avatar_url": current_user.avatar_url,
        "is_online": current_user.is_online,
        "last_seen": str(current_user.last_seen),
        "created_at": str(current_user.created_at),
    }


@app.post("/auth/upload-avatar", tags=["Auth"])
async def upload_avatar(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Upload a profile picture."""
    if file.content_type not in ALLOWED_IMAGE:
        raise HTTPException(status_code=400, detail="Only image files allowed for avatar")
    result = await upload_media(file)
    current_user.avatar_url = result["url"]
    db.commit()
    return {"msg": "Avatar updated ✅", "avatar_url": result["url"]}


# ══════════════════════════════════════════════
# USERS
# ══════════════════════════════════════════════

@app.get("/users", tags=["Users"])
def get_all_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all users in your app (scoped — only sees same app users)."""
    users = db.query(User).filter(
        User.app_id == current_user.app_id,
        User.id != current_user.id,
        User.is_banned == False
    ).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "avatar_url": u.avatar_url,
            "is_online": manager.is_online(u.app_id, u.username),
            "last_seen": str(u.last_seen),
        }
        for u in users
    ]


@app.get("/users/online", tags=["Users"])
def get_online_users(current_user: User = Depends(get_current_user)):
    return {"online_users": manager.online_in_app(current_user.app_id)}


# ══════════════════════════════════════════════
# DIRECT MESSAGES
# ══════════════════════════════════════════════

@app.post("/messages/send", tags=["Messages"])
async def send_message(
    msg: MessageSend,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    receiver = db.query(User).filter(
        User.username == msg.receiver_username,
        User.app_id == current_user.app_id
    ).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found in your app")
    if receiver.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot message yourself")

    new_msg = Message(
        content=msg.content,
        sender_id=current_user.id,
        receiver_id=receiver.id,
    )
    db.add(new_msg)
    db.commit()
    db.refresh(new_msg)

    await manager.send_to(current_user.app_id, receiver.username, {
        "type": "new_message",
        "message_id": new_msg.id,
        "from": current_user.username,
        "content": msg.content,
        "media_url": None,
        "media_type": None,
        "timestamp": str(new_msg.timestamp),
    })

    return {"msg": "Message sent ✅", "message_id": new_msg.id}


@app.post("/messages/send-media", tags=["Messages"])
async def send_media_message(
    receiver_username: str = Form(...),
    caption: str = Form(""),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Send an image, video, voice note, or file."""
    receiver = db.query(User).filter(
        User.username == receiver_username,
        User.app_id == current_user.app_id
    ).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found")

    uploaded = await upload_media(file)

    new_msg = Message(
        content=caption or None,
        media_url=uploaded["url"],
        media_type=uploaded["media_type"],
        sender_id=current_user.id,
        receiver_id=receiver.id,
    )
    db.add(new_msg)
    db.commit()
    db.refresh(new_msg)

    await manager.send_to(current_user.app_id, receiver.username, {
        "type": "new_message",
        "message_id": new_msg.id,
        "from": current_user.username,
        "content": caption or "",
        "media_url": uploaded["url"],
        "media_type": uploaded["media_type"],
        "timestamp": str(new_msg.timestamp),
    })

    return {
        "msg": "Media sent ✅",
        "message_id": new_msg.id,
        "media_url": uploaded["url"],
        "media_type": uploaded["media_type"],
    }


@app.get("/messages/{other_username}", tags=["Messages"])
def get_messages(
    other_username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    other = db.query(User).filter(
        User.username == other_username,
        User.app_id == current_user.app_id
    ).first()
    if not other:
        raise HTTPException(status_code=404, detail="User not found")

    msgs = (
        db.query(Message)
        .filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == other.id)) |
            ((Message.sender_id == other.id) & (Message.receiver_id == current_user.id))
        )
        .order_by(Message.timestamp.asc())
        .all()
    )

    for m in msgs:
        if m.receiver_id == current_user.id and not m.is_read:
            m.is_read = True
    db.commit()

    return [
        {
            "id": m.id,
            "content": m.content,
            "media_url": m.media_url,
            "media_type": m.media_type,
            "sender": m.sender.username,
            "receiver": m.receiver.username,
            "is_read": m.is_read,
            "timestamp": str(m.timestamp),
        }
        for m in msgs
    ]


@app.get("/messages/unread/count", tags=["Messages"])
def unread_count(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    count = db.query(Message).filter(
        Message.receiver_id == current_user.id, Message.is_read == False
    ).count()
    return {"unread_messages": count}


@app.delete("/messages/{message_id}", tags=["Messages"])
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


# ══════════════════════════════════════════════
# GROUP CHATS
# ══════════════════════════════════════════════

@app.post("/groups/create", tags=["Groups"])
def create_group(
    data: GroupCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group = Group(
        name=data.name.strip(),
        description=data.description,
        created_by=current_user.id,
        app_id=current_user.app_id,
    )
    group.members.append(current_user)
    db.add(group)
    db.commit()
    db.refresh(group)
    return {"msg": "Group created ✅", "group_id": group.id, "name": group.name}


@app.post("/groups/{group_id}/add/{username}", tags=["Groups"])
def add_member(
    group_id: int,
    username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group = db.query(Group).filter(Group.id == group_id, Group.app_id == current_user.app_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if group.created_by != current_user.id:
        raise HTTPException(status_code=403, detail="Only group creator can add members")

    user = db.query(User).filter(User.username == username, User.app_id == current_user.app_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user in group.members:
        raise HTTPException(status_code=400, detail="User already in group")

    group.members.append(user)
    db.commit()
    return {"msg": f"{username} added to group ✅"}


@app.delete("/groups/{group_id}/remove/{username}", tags=["Groups"])
def remove_member(
    group_id: int,
    username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group = db.query(Group).filter(Group.id == group_id, Group.app_id == current_user.app_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if group.created_by != current_user.id:
        raise HTTPException(status_code=403, detail="Only group creator can remove members")

    user = db.query(User).filter(User.username == username, User.app_id == current_user.app_id).first()
    if not user or user not in group.members:
        raise HTTPException(status_code=404, detail="User not in group")

    group.members.remove(user)
    db.commit()
    return {"msg": f"{username} removed from group ✅"}


@app.get("/groups", tags=["Groups"])
def get_my_groups(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return [
        {
            "id": g.id,
            "name": g.name,
            "description": g.description,
            "avatar_url": g.avatar_url,
            "member_count": len(g.members),
            "created_at": str(g.created_at),
        }
        for g in current_user.groups
    ]


@app.post("/groups/{group_id}/send", tags=["Groups"])
async def send_group_message(
    group_id: int,
    msg: GroupMessageSend,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group = db.query(Group).filter(Group.id == group_id, Group.app_id == current_user.app_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if current_user not in group.members:
        raise HTTPException(status_code=403, detail="You are not a member of this group")

    new_msg = GroupMessage(content=msg.content, sender_id=current_user.id, group_id=group.id)
    db.add(new_msg)
    db.commit()
    db.refresh(new_msg)

    member_usernames = [m.username for m in group.members]
    await manager.broadcast_group(current_user.app_id, member_usernames, {
        "type": "group_message",
        "group_id": group_id,
        "group_name": group.name,
        "message_id": new_msg.id,
        "from": current_user.username,
        "content": msg.content,
        "media_url": None,
        "timestamp": str(new_msg.timestamp),
    }, exclude=current_user.username)

    return {"msg": "Group message sent ✅", "message_id": new_msg.id}


@app.post("/groups/{group_id}/send-media", tags=["Groups"])
async def send_group_media(
    group_id: int,
    caption: str = Form(""),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group = db.query(Group).filter(Group.id == group_id, Group.app_id == current_user.app_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if current_user not in group.members:
        raise HTTPException(status_code=403, detail="Not a member")

    uploaded = await upload_media(file)
    new_msg = GroupMessage(
        content=caption or None,
        media_url=uploaded["url"],
        media_type=uploaded["media_type"],
        sender_id=current_user.id,
        group_id=group.id
    )
    db.add(new_msg)
    db.commit()
    db.refresh(new_msg)

    member_usernames = [m.username for m in group.members]
    await manager.broadcast_group(current_user.app_id, member_usernames, {
        "type": "group_message",
        "group_id": group_id,
        "group_name": group.name,
        "message_id": new_msg.id,
        "from": current_user.username,
        "content": caption,
        "media_url": uploaded["url"],
        "media_type": uploaded["media_type"],
        "timestamp": str(new_msg.timestamp),
    }, exclude=current_user.username)

    return {"msg": "Group media sent ✅", "media_url": uploaded["url"]}


@app.get("/groups/{group_id}/messages", tags=["Groups"])
def get_group_messages(
    group_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    group = db.query(Group).filter(Group.id == group_id, Group.app_id == current_user.app_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if current_user not in group.members:
        raise HTTPException(status_code=403, detail="Not a member")

    msgs = db.query(GroupMessage).filter(
        GroupMessage.group_id == group_id
    ).order_by(GroupMessage.timestamp.asc()).all()

    return [
        {
            "id": m.id,
            "content": m.content,
            "media_url": m.media_url,
            "media_type": m.media_type,
            "sender": m.sender.username,
            "timestamp": str(m.timestamp),
        }
        for m in msgs
    ]


# ══════════════════════════════════════════════
# WEBRTC SIGNALING (Voice & Video Calls)
# ══════════════════════════════════════════════

@app.post("/calls/signal", tags=["Calls"])
async def send_rtc_signal(
    signal: RTCSignal,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Send a WebRTC signal to another user for voice/video calls.
    signal_type: call-request | offer | answer | ice-candidate | call-end
    """
    target = db.query(User).filter(
        User.username == signal.to_username,
        User.app_id == current_user.app_id
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    if not manager.is_online(current_user.app_id, signal.to_username):
        raise HTTPException(status_code=400, detail="User is not online")

    await manager.send_to(current_user.app_id, signal.to_username, {
        "type": "rtc_signal",
        "signal_type": signal.signal_type,
        "from": current_user.username,
        "payload": signal.payload,
    })

    return {"msg": f"Signal '{signal.signal_type}' sent to {signal.to_username} ✅"}


# ══════════════════════════════════════════════
# WEBSOCKET
# ══════════════════════════════════════════════

@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        app_id = payload.get("app_id")
        if not user_id or not app_id:
            await websocket.close(code=4001)
            return
    except jwt.PyJWTError:
        await websocket.close(code=4001)
        return

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == int(user_id)).first()
        if not user or user.is_banned:
            await websocket.close(code=4001)
            return

        await manager.connect(app_id, user.username, websocket)

        user.is_online = True
        user.last_seen = datetime.utcnow()
        db.commit()

        await manager.broadcast_app(app_id, {
            "type": "presence",
            "username": user.username,
            "status": "online"
        }, exclude=user.username)

        unread = db.query(Message).filter(
            Message.receiver_id == user.id, Message.is_read == False
        ).count()
        await manager.send_to(app_id, user.username, {"type": "unread_count", "count": unread})

        try:
            while True:
                data = await websocket.receive_text()
                try:
                    parsed = json.loads(data)
                    if parsed.get("type") == "ping":
                        await manager.send_to(app_id, user.username, {"type": "pong"})
                except Exception:
                    pass
        except WebSocketDisconnect:
            pass

    finally:
        manager.disconnect(app_id, user.username)
        db2 = SessionLocal()
        try:
            u = db2.query(User).filter(User.id == int(user_id)).first()
            if u:
                u.is_online = False
                u.last_seen = datetime.utcnow()
                db2.commit()
        finally:
            db2.close()
        db.close()

        await manager.broadcast_app(app_id, {
            "type": "presence",
            "username": user.username,
            "status": "offline"
        })


# ══════════════════════════════════════════════
# ADMIN DASHBOARD (HTML)
# ══════════════════════════════════════════════

@app.get("/admin/dashboard", response_class=HTMLResponse, tags=["Admin"])
def admin_dashboard(
    x_admin_secret: str = Header(..., alias="X-Admin-Secret"),
    db: Session = Depends(get_db)
):
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Admin access denied")

    apps = db.query(DeveloperApp).all()
    users = db.query(User).all()
    messages = db.query(Message).count()
    groups = db.query(Group).count()

    apps_rows = "".join([
        f"<tr><td>{a.id}</td><td>{a.app_name}</td><td>{a.developer_email}</td>"
        f"<td><code>{a.api_key[:16]}...</code></td>"
        f"<td>{'✅ Active' if a.is_active else '❌ Suspended'}</td>"
        f"<td>{str(a.created_at)[:10]}</td></tr>"
        for a in apps
    ])

    users_rows = "".join([
        f"<tr><td>{u.id}</td><td>{u.username}</td><td>{u.email}</td>"
        f"<td>{db.query(DeveloperApp).filter(DeveloperApp.id==u.app_id).first().app_name}</td>"
        f"<td>{'🟢 Online' if manager.is_online(u.app_id, u.username) else '⚫ Offline'}</td>"
        f"<td>{'🚫 Banned' if u.is_banned else '✅ Active'}</td>"
        f"<td>{str(u.created_at)[:10]}</td></tr>"
        for u in users
    ])

    return f"""<!DOCTYPE html>
<html>
<head>
<title>OX-Bridge Admin</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{font-family:monospace;background:#050d1a;color:#c8dff5;padding:20px}}
  h1{{color:#00e5ff;font-size:22px;margin-bottom:4px;letter-spacing:3px}}
  .sub{{color:#4a6a8a;font-size:12px;margin-bottom:24px;letter-spacing:1px}}
  .stats{{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:28px}}
  .stat{{background:#0a1628;border:1px solid #1a3a5c;border-radius:6px;padding:16px 24px;min-width:120px}}
  .stat .num{{font-size:28px;color:#00e5ff;font-weight:bold}}
  .stat .label{{font-size:11px;color:#4a6a8a;letter-spacing:1px;margin-top:2px}}
  h2{{color:#00e5ff;font-size:14px;letter-spacing:2px;margin-bottom:12px;margin-top:24px}}
  table{{width:100%;border-collapse:collapse;background:#0a1628;border-radius:6px;overflow:hidden}}
  th{{background:#0f1f38;color:#4a6a8a;font-size:11px;letter-spacing:1px;padding:10px 12px;text-align:left}}
  td{{padding:10px 12px;border-top:1px solid #1a3a5c;font-size:13px}}
  code{{background:#0f1f38;padding:2px 6px;border-radius:3px;color:#00e5ff;font-size:11px}}
  .online-count{{color:#00ff88;font-weight:bold}}
</style>
</head>
<body>
<h1>OX-BRIDGE ADMIN</h1>
<div class="sub">PLATFORM DASHBOARD · v3.0.0</div>
<div class="stats">
  <div class="stat"><div class="num">{len(apps)}</div><div class="label">APPS</div></div>
  <div class="stat"><div class="num">{len(users)}</div><div class="label">USERS</div></div>
  <div class="stat"><div class="num">{messages}</div><div class="label">MESSAGES</div></div>
  <div class="stat"><div class="num">{groups}</div><div class="label">GROUPS</div></div>
  <div class="stat"><div class="num online-count">{sum(1 for u in users if manager.is_online(u.app_id, u.username))}</div><div class="label">ONLINE NOW</div></div>
</div>

<h2>DEVELOPER APPS</h2>
<table>
<tr><th>ID</th><th>APP NAME</th><th>EMAIL</th><th>API KEY</th><th>STATUS</th><th>CREATED</th></tr>
{apps_rows or '<tr><td colspan="6" style="text-align:center;color:#4a6a8a">No apps yet</td></tr>'}
</table>

<h2>ALL USERS</h2>
<table>
<tr><th>ID</th><th>USERNAME</th><th>EMAIL</th><th>APP</th><th>STATUS</th><th>ACCOUNT</th><th>JOINED</th></tr>
{users_rows or '<tr><td colspan="7" style="text-align:center;color:#4a6a8a">No users yet</td></tr>'}
</table>
</body>
</html>"""


@app.post("/admin/ban/{user_id}", tags=["Admin"])
def ban_user(user_id: int, _=Depends(get_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_banned = True
    db.commit()
    return {"msg": f"User {user.username} banned ✅"}


@app.post("/admin/unban/{user_id}", tags=["Admin"])
def unban_user(user_id: int, _=Depends(get_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_banned = False
    db.commit()
    return {"msg": f"User {user.username} unbanned ✅"}


@app.post("/admin/suspend-app/{app_id}", tags=["Admin"])
def suspend_app(app_id: int, _=Depends(get_admin), db: Session = Depends(get_db)):
    dev_app = db.query(DeveloperApp).filter(DeveloperApp.id == app_id).first()
    if not dev_app:
        raise HTTPException(status_code=404, detail="App not found")
    dev_app.is_active = False
    db.commit()
    return {"msg": f"App '{dev_app.app_name}' suspended ✅"}


@app.get("/admin/apps", tags=["Admin"])
def list_all_apps(_=Depends(get_admin), db: Session = Depends(get_db)):
    apps = db.query(DeveloperApp).all()
    return [
        {
            "id": a.id,
            "app_name": a.app_name,
            "developer_email": a.developer_email,
            "is_active": a.is_active,
            "user_count": db.query(User).filter(User.app_id == a.id).count(),
            "created_at": str(a.created_at),
        }
        for a in apps
    ]
