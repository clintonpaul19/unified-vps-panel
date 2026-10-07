from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse
from starlette.middleware.gzip import GZipMiddleware
from sqlalchemy import and_, desc, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from .db import Base, SessionLocal, engine
from .models import AuditEvent, Command, Membership, Organization, Server, ServerToken, User
from .schemas import BootstrapRequest, CommandCreate, CommandResult, CommandOut, HeartbeatIn, LoginRequest, OrganizationOut, ServerCreate, ServerOut, UserOut
from .security import hash_password, make_session, new_node_token, read_session, token_hash, verify_password

SESSION_COOKIE = "uvps_session"
ROLE_WRITE = {"owner", "admin", "operator"}

@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.auto_create_schema:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()

app = FastAPI(title=settings.app_name, version="0.3.0", docs_url="/docs", redoc_url="/redoc", lifespan=lifespan)
app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)

async def get_db():
    async with SessionLocal() as db:
        yield db

async def current_user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    sid = request.cookies.get(SESSION_COOKIE)
    if not sid:
        raise HTTPException(status_code=401, detail="authentication required")
    uid = read_session(sid)
    if not uid:
        raise HTTPException(status_code=401, detail="invalid session")
    try:
        user = await db.get(User, UUID(uid))
    except (ValueError, TypeError):
        raise HTTPException(status_code=401, detail="invalid session")
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="user unavailable")
    return user

async def user_memberships(db: AsyncSession, user_id: UUID):
    return (await db.execute(select(Organization, Membership.role).join(Membership, Membership.organization_id == Organization.id).where(Membership.user_id == user_id).order_by(Organization.name))).all()

async def current_membership(request: Request, db: AsyncSession, user: User) -> tuple[Organization, str]:
    requested = request.headers.get("X-Organization-ID")
    stmt = (
        select(Organization, Membership.role)
        .join(Membership, Membership.organization_id == Organization.id)
        .where(Membership.user_id == user.id)
    )
    if requested:
        try:
            stmt = stmt.where(Organization.id == UUID(requested))
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid organization id")
        row = (await db.execute(stmt.limit(1))).first()
        if not row:
            raise HTTPException(status_code=404, detail="organization not found")
        return row[0], row[1]
    rows = (await db.execute(stmt.limit(2))).all()
    if not rows:
        raise HTTPException(status_code=403, detail="organization membership required")
    if len(rows) != 1:
        raise HTTPException(status_code=400, detail="X-Organization-ID is required for multi-organization users")
    return rows[0][0], rows[0][1]

async def current_org(request: Request, db: AsyncSession, user: User) -> Organization:
    org, _role = await current_membership(request, db, user)
    return org

async def record_event(db: AsyncSession, org_id: UUID, actor_user_id: UUID | None, server_id: UUID | None, event_type: str, metadata: dict) -> None:
    db.add(AuditEvent(organization_id=org_id, actor_user_id=actor_user_id, server_id=server_id, event_type=event_type, metadata=metadata))

async def bootstrap(db: AsyncSession, organization_name: str) -> User:
    email = settings.bootstrap_admin_email.strip().lower()
    password = settings.bootstrap_admin_password
    if not email or not password:
        raise HTTPException(status_code=503, detail="bootstrap credentials are not configured")
    if await db.scalar(select(User.id).limit(1)) is not None:
        raise HTTPException(status_code=409, detail="control plane is already bootstrapped")
    slug_base = "".join(c if c.isalnum() else "-" for c in organization_name.lower()).strip("-")[:70] or "unified-vps"
    org = Organization(name=organization_name, slug=f"{slug_base}-{hashlib.sha1(email.encode()).hexdigest()[:8]}")
    user = User(email=email, password_hash=hash_password(password))
    db.add_all([org, user])
    await db.flush()
    db.add(Membership(organization_id=org.id, user_id=user.id, role="owner"))
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="control plane is already bootstrapped")
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
async def bootstrap_route(
    body: BootstrapRequest,
    db: AsyncSession = Depends(get_db),
    x_bootstrap_token: str | None = Header(default=None, alias="X-Bootstrap-Token"),
) -> dict:
    if settings.bootstrap_token and not (
        x_bootstrap_token and hmac.compare_digest(x_bootstrap_token, settings.bootstrap_token)
    ):
        raise HTTPException(status_code=403, detail="bootstrap token required")
    user = await bootstrap(db, body.organization_name)
    return {"created_for": user.email}

@app.post("/v1/auth/login")
async def login(body: LoginRequest, response: Response, db: AsyncSession = Depends(get_db)):
    user = await db.scalar(select(User).where(User.email == body.email.lower()).limit(1))
    if not user or not user.is_active or not verify_password(user.password_hash, body.password):
        raise HTTPException(status_code=401, detail="invalid credentials")
    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()
    response.set_cookie(SESSION_COOKIE, make_session(str(user.id)), httponly=True, secure=settings.cookie_secure, samesite="lax", max_age=settings.session_ttl_seconds, path="/")
    return {"user": UserOut.model_validate(user).model_dump()}

@app.post("/v1/auth/logout")
async def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE, path="/", secure=settings.cookie_secure, httponly=True, samesite="lax")
    return {"ok": True}

@app.get("/v1/me")
async def me(user: User = Depends(current_user)):
    return UserOut.model_validate(user)

@app.get("/v1/organizations", response_model=list[OrganizationOut])
async def list_organizations(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    return [OrganizationOut.model_validate(org) for org, _role in await user_memberships(db, user.id)]

async def scoped_server(db: AsyncSession, user: User, server_id: UUID, request: Request):
    org = await current_org(request, db, user)
    server = await db.get(Server, server_id)
    if not server or server.organization_id != org.id:
        raise HTTPException(status_code=404, detail="server not found")
    return org, server

async def scoped_write_server(db: AsyncSession, user: User, server_id: UUID, request: Request):
    org, role = await current_membership(request, db, user)
    if role not in ROLE_WRITE:
        raise HTTPException(status_code=403, detail="write access required")
    server = await db.get(Server, server_id)
    if not server or server.organization_id != org.id:
        raise HTTPException(status_code=404, detail="server not found")
    return org, server

@app.get("/v1/servers", response_model=list[ServerOut])
async def list_servers(request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    org = await current_org(request, db, user)
    return (await db.execute(select(Server).where(Server.organization_id == org.id).order_by(desc(Server.updated_at)))).scalars().all()

@app.get("/v1/servers/{server_id}", response_model=ServerOut)
async def get_server(server_id: UUID, request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    _, server = await scoped_server(db, user, server_id, request)
    return server

@app.post("/v1/servers")
async def create_server(body: ServerCreate, request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    org, role = await current_membership(request, db, user)
    if role not in ROLE_WRITE:
        raise HTTPException(status_code=403, detail="write access required")
    server = Server(organization_id=org.id, name=body.name, hostname=body.hostname, public_ipv4=body.public_ipv4, public_ipv6=body.public_ipv6, status="provisioning")
    db.add(server)
    await db.flush()
    raw = new_node_token()
    db.add(ServerToken(server_id=server.id, token_hash=token_hash(raw)))
    await record_event(db, org.id, user.id, server.id, "server.created", {"name": server.name})
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="server name already exists in this organization")
    return {"server": ServerOut.model_validate(server), "node_token": raw}

async def authenticated_agent(db: AsyncSession, server_id: UUID, authorization: str | None) -> Server:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="agent token required")
    raw = authorization[7:].strip()
    if not raw:
        raise HTTPException(status_code=401, detail="agent token required")
    digest = token_hash(raw)
    server = await db.scalar(select(Server).join(ServerToken, ServerToken.server_id == Server.id).where(and_(Server.id == server_id, ServerToken.token_hash == digest, ServerToken.revoked_at.is_(None))).limit(1))
    if not server:
        raise HTTPException(status_code=401, detail="invalid agent token")
    return server

@app.post("/v1/servers/{server_id}/heartbeat")
async def heartbeat(server_id: UUID, body: HeartbeatIn, request: Request, db: AsyncSession = Depends(get_db)):
    server = await authenticated_agent(db, server_id, request.headers.get("Authorization"))
    server.agent_version = body.agent_version
    server.hostname = body.hostname or server.hostname
    server.public_ipv4 = body.public_ipv4 or server.public_ipv4
    server.public_ipv6 = body.public_ipv6 or server.public_ipv6
    server.status = body.status
    server.metrics = body.metrics
    server.last_seen_at = datetime.now(timezone.utc)
    await db.commit()
    return {"ok": True, "server_id": str(server.id)}

@app.post("/v1/servers/{server_id}/tokens")
async def rotate_server_token(server_id: UUID, request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    org, server = await scoped_write_server(db, user, server_id, request)
    await db.execute(update(ServerToken).where(and_(ServerToken.server_id == server.id, ServerToken.revoked_at.is_(None))).values(revoked_at=datetime.now(timezone.utc)))
    raw = new_node_token()
    db.add(ServerToken(server_id=server.id, token_hash=token_hash(raw)))
    await record_event(db, org.id, user.id, server.id, "server.token_rotated", {})
    await db.commit()
    return {"node_token": raw}

@app.get("/v1/servers/{server_id}/commands/next", response_model=CommandOut | None)
async def next_command(server_id: UUID, request: Request, db: AsyncSession = Depends(get_db)):
    server = await authenticated_agent(db, server_id, request.headers.get("Authorization"))
    now = datetime.now(timezone.utc)
    result = await db.execute(select(Command).where(and_(Command.server_id == server.id, Command.attempt_count < 5, or_(Command.status == "queued", and_(Command.status.in_({"sent","running"}), Command.lease_until < now)))).order_by(Command.created_at).with_for_update(skip_locked=True).limit(1))
    cmd = result.scalar_one_or_none()
    if not cmd:
        await db.commit()
        return None
    cmd.status = "sent"
    cmd.lease_until = now + timedelta(seconds=settings.command_lease_seconds)
    cmd.attempt_count += 1
    await db.commit()
    return cmd

@app.post("/v1/servers/{server_id}/commands/{command_id}/result", response_model=CommandOut)
async def command_result(server_id: UUID, command_id: UUID, request: Request, result_payload: CommandResult, db: AsyncSession = Depends(get_db)):
    server = await authenticated_agent(db, server_id, request.headers.get("Authorization"))
    cmd = await db.get(Command, command_id)
    if not cmd or cmd.server_id != server.id:
        raise HTTPException(status_code=404, detail="command not found")
    status_value = result_payload.status
    if cmd.status in {"succeeded","failed","cancelled"}:
        return cmd
    now = datetime.now(timezone.utc)
    if status_value == "running":
        cmd.started_at = cmd.started_at or now
        cmd.lease_until = now + timedelta(seconds=settings.command_lease_seconds)
    else:
        cmd.finished_at = now
        cmd.lease_until = None
    cmd.status = status_value
    if result_payload.result is not None:
        cmd.result = result_payload.result
    if status_value == "failed":
        cmd.error = str(result_payload.error or "command failed")[:2000]
    await db.commit()
    return cmd

@app.post("/v1/servers/{server_id}/commands/{command_id}/cancel", response_model=CommandOut)
async def cancel_command(server_id: UUID, command_id: UUID, request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    org, server = await scoped_write_server(db, user, server_id, request)
    cmd = await db.get(Command, command_id)
    if not cmd or cmd.organization_id != org.id or cmd.server_id != server.id:
        raise HTTPException(status_code=404, detail="command not found")
    if cmd.status not in {"queued","sent"}:
        raise HTTPException(status_code=409, detail="command cannot be cancelled")
    cmd.status = "cancelled"
    cmd.finished_at = datetime.now(timezone.utc)
    cmd.lease_until = None
    await record_event(db, org.id, user.id, server.id, "command.cancelled", {"command_id": str(command_id)})
    await db.commit()
    return cmd

@app.post("/v1/servers/{server_id}/commands", response_model=CommandOut)
async def create_command(server_id: UUID, body: CommandCreate, request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    org, server = await scoped_write_server(db, user, server_id, request)
    cmd = Command(organization_id=org.id, server_id=server.id, command_type=body.command_type, payload=body.payload, requested_by=user.id, idempotency_key=body.idempotency_key)
    db.add(cmd)
    await record_event(db, org.id, user.id, server.id, "command.queued", {"type": body.command_type})
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        if body.idempotency_key:
            existing = await db.scalar(select(Command).where(and_(Command.organization_id == org.id, Command.idempotency_key == body.idempotency_key)))
            if existing:
                return existing
        raise HTTPException(status_code=409, detail="command creation conflicted with another request")
    return cmd

@app.get("/v1/servers/{server_id}/commands", response_model=list[CommandOut])
async def list_commands(server_id: UUID, request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    _, server = await scoped_server(db, user, server_id, request)
    return (await db.execute(select(Command).where(Command.server_id == server.id).order_by(desc(Command.created_at)).limit(100))).scalars().all()

@app.get("/v1/events")
async def events(request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    org = await current_org(request, db, user)
    rows = (await db.execute(select(AuditEvent).where(AuditEvent.organization_id == org.id).order_by(desc(AuditEvent.created_at)).limit(100))).scalars().all()
    return [{"id": r.id, "event_type": r.event_type, "server_id": str(r.server_id) if r.server_id else None, "metadata": r.metadata, "created_at": r.created_at} for r in rows]

@app.get("/")
async def index():
    return FileResponse("/app/web/index.html")

@app.get("/readyz")
async def readyz():
    return await healthz()