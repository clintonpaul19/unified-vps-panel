from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from datetime import datetime, timezone
import hashlib
from uuid import UUID

from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from sqlalchemy import and_, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .db import Base, engine, SessionLocal
from .models import AuditEvent, Command, Membership, Organization, Server, ServerToken, User
from .schemas import BootstrapRequest, CommandCreate, CommandOut, HeartbeatIn, LoginRequest, ServerCreate, ServerOut, UserOut
from .security import hash_password, make_session, new_node_token, read_session, token_hash, verify_password

SESSION_COOKIE="uvps_session"
ROLE_WRITE={"owner","admin","operator"}

@asynccontextmanager
async def lifespan(_: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()

app=FastAPI(title=settings.app_name, version="0.1.0", docs_url="/docs", redoc_url="/redoc", lifespan=lifespan)

async def get_db() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as db:
        yield db

async def current_user(request: Request, db: AsyncSession=Depends(get_db)) -> User:
    sid=request.cookies.get(SESSION_COOKIE)
    if not sid:
        raise HTTPException(status_code=401, detail="authentication required")
    uid=read_session(sid)
    if not uid:
        raise HTTPException(status_code=401, detail="invalid session")
    user=await db.get(User, UUID(uid))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="user unavailable")
    return user

async def org_for_user(db: AsyncSession, user: User) -> Organization:
    result=await db.execute(select(Organization).join(Membership).where(Membership.user_id==user.id).limit(1))
    org=result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=403, detail="organization membership required")
    return org

async def write_access(db: AsyncSession, user: User, org: Organization) -> bool:
    result=await db.execute(select(Membership.role).where(and_(Membership.organization_id==org.id, Membership.user_id==user.id)))
    return result.scalar_one_or_none() in ROLE_WRITE

async def record_event(db, org_id, actor_user_id, server_id, event_type, metadata):
    db.add(AuditEvent(organization_id=org_id, actor_user_id=actor_user_id, server_id=server_id, event_type=event_type, metadata=metadata))

async def bootstrap(db: AsyncSession, organization_name: str) -> User:
    email=settings.bootstrap_admin_email.strip().lower()
    password=settings.bootstrap_admin_password
    if not email or not password:
        raise HTTPException(status_code=503, detail="bootstrap credentials are not configured")
    existing=(await db.execute(select(User).where(User.email==email))).scalar_one_or_none()
    if existing:
        return existing
    slug="".join(c if c.isalnum() else "-" for c in organization_name.lower()).strip("-")[:70] or "unified-vps"
    org=Organization(name=organization_name,slug=f"{slug}-{hashlib.sha1(email.encode()).hexdigest()[:8]}")
    user=User(email=email,password_hash=hash_password(password))
    db.add_all([org,user])
    await db.flush()
    db.add(Membership(organization_id=org.id,user_id=user.id,role="owner"))
    await db.commit()
    return user

@app.get("/healthz")
async def healthz():
    try:
        async with engine.connect() as conn:
            await conn.exec_driver_sql("select 1")
        return {"status":"ok","service":"control-plane"}
    except Exception:
        raise HTTPException(status_code=503, detail="database unavailable")

@app.post("/v1/auth/bootstrap")
async def bootstrap_route(body: BootstrapRequest, db: AsyncSession=Depends(get_db)):
    user=await bootstrap(db, body.organization_name)
    return {"created_for":user.email}

@app.post("/v1/auth/login")
async def login(body: LoginRequest, response: Response, db: AsyncSession=Depends(get_db)):
    email=body.email.lower()
    user=(await db.execute(select(User).where(User.email==email))).scalar_one_or_none()
    if not user or not user.is_active or not verify_password(user.password_hash,body.password):
        raise HTTPException(status_code=401, detail="invalid credentials")
    user.last_login_at=datetime.now(timezone.utc)
    await db.commit()
    response.set_cookie(SESSION_COOKIE,make_session(str(user.id)),httponly=True,secure=settings.cookie_secure,samesite="lax",max_age=settings.session_ttl_seconds,path="/")
    return {"user":UserOut.model_validate(user).model_dump()}

@app.post("/v1/auth/logout")
async def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE,path="/")
    return {"ok":True}

@app.get("/v1/me")
async def me(user: User=Depends(current_user)):
    return UserOut.model_validate(user)

@app.get("/v1/servers", response_model=list[ServerOut])
async def list_servers(user: User=Depends(current_user),db: AsyncSession=Depends(get_db)):
    org=await org_for_user(db,user)
    rows=(await db.execute(select(Server).where(Server.organization_id==org.id).order_by(desc(Server.updated_at)))).scalars().all()
    return rows

@app.post("/v1/servers")
async def create_server(body: ServerCreate,user: User=Depends(current_user),db: AsyncSession=Depends(get_db)):
    org=await org_for_user(db,user)
    if not await write_access(db,user,org):
        raise HTTPException(status_code=403,detail="write access required")
    server=Server(organization_id=org.id,name=body.name,hostname=body.hostname,public_ipv4=body.public_ipv4,public_ipv6=body.public_ipv6,status="provisioning")
    db.add(server)
    await db.flush()
    raw=new_node_token()
    db.add(ServerToken(server_id=server.id,token_hash=token_hash(raw)))
    await record_event(db,org.id,user.id,server.id,"server.created",{"name":server.name})
    await db.commit()
    return {"server":ServerOut.model_validate(server),"node_token":raw}

async def authenticated_agent(db: AsyncSession, server_id: UUID, authorization: str | None) -> Server:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401,detail="agent token required")
    digest=token_hash(authorization[7:].strip())
    result=await db.execute(select(Server).join(ServerToken).where(and_(Server.id==server_id,ServerToken.token_hash==digest,ServerToken.revoked_at.is_(None))))
    server=result.scalar_one_or_none()
    if not server:
        raise HTTPException(status_code=401,detail="invalid agent token")
    return server

@app.post("/v1/servers/{server_id}/heartbeat")
async def heartbeat(server_id: UUID, body: HeartbeatIn, request: Request, db: AsyncSession=Depends(get_db)):
    server=await authenticated_agent(db,server_id,request.headers.get("Authorization"))
    server.agent_version=body.agent_version
    server.hostname=body.hostname or server.hostname
    server.public_ipv4=body.public_ipv4 or server.public_ipv4
    server.public_ipv6=body.public_ipv6 or server.public_ipv6
    server.status=body.status
    server.last_seen_at=datetime.now(timezone.utc)
    await db.commit()
    return {"ok":True,"server_id":str(server.id)}

@app.get("/v1/servers/{server_id}/commands/next", response_model=CommandOut | None)
async def next_command(server_id: UUID, request: Request, db: AsyncSession=Depends(get_db)):
    server=await authenticated_agent(db,server_id,request.headers.get("Authorization"))
    result=await db.execute(
        select(Command)
        .where(and_(Command.server_id==server.id,Command.status=="queued"))
        .order_by(Command.created_at)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    cmd=result.scalar_one_or_none()
    if not cmd:
        await db.commit()
        return None
    cmd.status="sent"
    await db.commit()
    await db.refresh(cmd)
    return cmd

@app.post("/v1/servers/{server_id}/commands/{command_id}/result", response_model=CommandOut)
async def command_result(
    server_id: UUID,
    command_id: UUID,
    request: Request,
    result_payload: dict,
    db: AsyncSession=Depends(get_db),
):
    server=await authenticated_agent(db,server_id,request.headers.get("Authorization"))
    cmd=await db.get(Command,command_id)
    if not cmd or cmd.server_id!=server.id:
        raise HTTPException(status_code=404,detail="command not found")
    status_value=result_payload.get("status")
    if status_value not in {"running","succeeded","failed"}:
        raise HTTPException(status_code=400,detail="status must be running, succeeded or failed")
    now=datetime.now(timezone.utc)
    cmd.status=status_value
    if status_value=="running" and cmd.started_at is None:
        cmd.started_at=now
    if status_value in {"succeeded","failed"}:
        cmd.finished_at=now
    if "result" in result_payload and isinstance(result_payload["result"],dict):
        cmd.result=result_payload["result"]
    if status_value=="failed":
        cmd.error=str(result_payload.get("error","command failed"))[:2000]
    await db.commit()
    await db.refresh(cmd)
    return cmd

@app.post("/v1/servers/{server_id}/commands/{command_id}/cancel", response_model=CommandOut)
async def cancel_command(server_id: UUID, command_id: UUID, user: User=Depends(current_user), db: AsyncSession=Depends(get_db)):
    org=await org_for_user(db,user)
    if not await write_access(db,user,org):
        raise HTTPException(status_code=403,detail="write access required")
    cmd=await db.get(Command,command_id)
    if not cmd or cmd.organization_id!=org.id or cmd.server_id!=server_id or cmd.status not in {"queued","sent"}:
        raise HTTPException(status_code=404,detail="cancellable command not found")
    cmd.status="cancelled"
    cmd.finished_at=datetime.now(timezone.utc)
    await record_event(db,org.id,user.id,server_id,"command.cancelled",{"command_id":str(command_id)})
    await db.commit()
    await db.refresh(cmd)
    return cmd

@app.post("/v1/servers/{server_id}/commands", response_model=CommandOut)
async def create_command(server_id: UUID, body: CommandCreate,user: User=Depends(current_user),db: AsyncSession=Depends(get_db),):
    org=await org_for_user(db,user)
    if not await write_access(db,user,org):
        raise HTTPException(status_code=403,detail="write access required")
    server=await db.get(Server,server_id)
    if not server or server.organization_id!=org.id:
        raise HTTPException(status_code=404,detail="server not found")
    existing=None
    if body.idempotency_key:
        existing=(await db.execute(select(Command).where(and_(Command.organization_id==org.id,Command.idempotency_key==body.idempotency_key)))).scalar_one_or_none()
        if existing:
            return existing
    cmd=Command(organization_id=org.id,server_id=server.id,command_type=body.command_type,payload=body.payload,requested_by=user.id,idempotency_key=body.idempotency_key)
    db.add(cmd)
    await record_event(db,org.id,user.id,server.id,"command.queued",{"type":body.command_type})
    await db.commit()
    await db.refresh(cmd)
    return cmd

@app.get("/v1/servers/{server_id}/commands", response_model=list[CommandOut])
async def list_commands(server_id: UUID,user: User=Depends(current_user),db: AsyncSession=Depends(get_db)):
    org=await org_for_user(db,user)
    server=await db.get(Server,server_id)
    if not server or server.organization_id!=org.id:
        raise HTTPException(status_code=404,detail="server not found")
    return (await db.execute(select(Command).where(Command.server_id==server_id).order_by(desc(Command.created_at)).limit(100))).scalars().all()

@app.get("/v1/events")
async def events(user: User=Depends(current_user),db: AsyncSession=Depends(get_db)):
    org=await org_for_user(db,user)
    rows=(await db.execute(select(AuditEvent).where(AuditEvent.organization_id==org.id).order_by(desc(AuditEvent.created_at)).limit(100))).scalars().all()
    return [{"id":r.id,"event_type":r.event_type,"server_id":str(r.server_id) if r.server_id else None,"metadata":r.metadata,"created_at":r.created_at} for r in rows]

@app.get("/")
async def index():
    return FileResponse("/app/web/index.html")

@app.get("/readyz")
async def readyz():
    return await healthz()
