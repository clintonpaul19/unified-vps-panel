from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse
from sqlalchemy import and_, desc, or_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.gzip import GZipMiddleware

from .config import settings
from .db import Base, SessionLocal, engine
from .middleware import RequestContextMiddleware
from .models import AuditEvent, Command, Membership, Organization, Server, ServerToken, User
from .pagination import Cursor, InvalidCursor, decode_cursor, encode_cursor
from .schemas import (
    BootstrapRequest,
    CommandCreate,
    CommandOut,
    CommandResult,
    HeartbeatIn,
    LoginRequest,
    OrganizationOut,
    ServerCreate,
    ServerOut,
    UserOut,
)
from .security import hash_password, make_session, new_node_token, read_session, token_hash, verify_password


SESSION_COOKIE = "uvps_session"
ROLE_WRITE = {"owner", "admin", "operator"}
BOOTSTRAP_LOCK_KEY = 193847201


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.auto_create_schema:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(
    title=settings.app_name,
    version="0.4.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)
app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)
app.add_middleware(RequestContextMiddleware)


def cursor_secret() -> str:
    return settings.session_secret or "development-cursor-secret"


def parse_cursor(value: str | None, kind: str) -> Cursor | None:
    if not value:
        return None
    try:
        return decode_cursor(value=value, kind=kind, secret=cursor_secret())
    except InvalidCursor as exc:
        raise HTTPException(status_code=400, detail="invalid pagination cursor") from exc


def normalize_limit(limit: int) -> int:
    return max(1, min(limit, settings.max_page_size))


def set_page_headers(response: Response, limit: int, next_cursor: str | None) -> None:
    response.headers["X-Page-Limit"] = str(limit)
    if next_cursor:
        response.headers["X-Next-Cursor"] = next_cursor


def effective_status_value(status: str, last_seen_at: datetime | None, now: datetime) -> str:
    if status == "provisioning":
        return "provisioning"
    if status == "offline":
        return "offline"
    if not last_seen_at or last_seen_at < now - timedelta(seconds=settings.heartbeat_offline_seconds):
        return "offline"
    return status


def effective_server_status(server: Server, now: datetime) -> str:
    return effective_status_value(server.status, server.last_seen_at, now)


def server_output(server: Server, now: datetime, include_metrics: bool = True) -> ServerOut:
    return ServerOut(
        id=server.id,
        name=server.name,
        hostname=server.hostname,
        public_ipv4=server.public_ipv4,
        public_ipv6=server.public_ipv6,
        agent_version=server.agent_version,
        status=effective_server_status(server, now),
        metrics=server.metrics if include_metrics else {},
        last_seen_at=server.last_seen_at,
    )


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
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=401, detail="invalid session") from exc
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="user unavailable")
    return user


async def user_memberships(db: AsyncSession, user_id: UUID):
    return (
        await db.execute(
            select(Organization, Membership.role)
            .join(Membership, Membership.organization_id == Organization.id)
            .where(Membership.user_id == user_id)
            .order_by(Organization.name)
        )
    ).all()


async def current_membership(
    request: Request,
    db: AsyncSession,
    user: User,
) -> tuple[Organization, str]:
    requested = request.headers.get("X-Organization-ID")
    stmt = (
        select(Organization, Membership.role)
        .join(Membership, Membership.organization_id == Organization.id)
        .where(Membership.user_id == user.id)
    )
    if requested:
        try:
            stmt = stmt.where(Organization.id == UUID(requested))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid organization id") from exc
        row = (await db.execute(stmt.limit(1))).first()
        if not row:
            raise HTTPException(status_code=404, detail="organization not found")
        return row[0], row[1]

    rows = (await db.execute(stmt.limit(2))).all()
    if not rows:
        raise HTTPException(status_code=403, detail="organization membership required")
    if len(rows) != 1:
        raise HTTPException(
            status_code=400,
            detail="X-Organization-ID is required for multi-organization users",
        )
    return rows[0][0], rows[0][1]


async def current_org(request: Request, db: AsyncSession, user: User) -> Organization:
    org, _role = await current_membership(request, db, user)
    return org


async def record_event(
    db: AsyncSession,
    org_id: UUID,
    actor_user_id: UUID | None,
    server_id: UUID | None,
    event_type: str,
    metadata: dict,
) -> None:
    db.add(
        AuditEvent(
            organization_id=org_id,
            actor_user_id=actor_user_id,
            server_id=server_id,
            event_type=event_type,
            metadata=metadata,
        )
    )


async def bootstrap(db: AsyncSession, organization_name: str) -> User:
    # Serialize first-run initialization across API replicas. PostgreSQL
    # advisory locks are transaction-scoped and require no extra table.
    await db.execute(text(f"SELECT pg_advisory_xact_lock({BOOTSTRAP_LOCK_KEY})"))

    email = settings.bootstrap_admin_email.strip().lower()
    password = settings.bootstrap_admin_password
    if not email or not password:
        raise HTTPException(status_code=503, detail="bootstrap credentials are not configured")
    if await db.scalar(select(User.id).limit(1)) is not None:
        raise HTTPException(status_code=409, detail="control plane is already bootstrapped")

    slug_base = "".join(
        c if c.isalnum() else "-" for c in organization_name.lower()
    ).strip("-")[:70] or "unified-vps"
    org = Organization(
        name=organization_name,
        slug=f"{slug_base}-{hashlib.sha1(email.encode()).hexdigest()[:8]}",
    )
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
    return {"status": "ok", "service": "control-plane"}


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
async def login(
    body: LoginRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(
        select(User).where(User.email == body.email.lower()).limit(1)
    )
    if not user or not user.is_active or not verify_password(user.password_hash, body.password):
        raise HTTPException(status_code=401, detail="invalid credentials")
    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()
    response.set_cookie(
        SESSION_COOKIE,
        make_session(str(user.id)),
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        max_age=settings.session_ttl_seconds,
        path="/",
    )
    return {"user": UserOut.model_validate(user).model_dump()}


@app.post("/v1/auth/logout")
async def logout(response: Response):
    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        secure=settings.cookie_secure,
        httponly=True,
        samesite="lax",
    )
    return {"ok": True}


@app.get("/v1/me")
async def me(user: User = Depends(current_user)):
    return UserOut.model_validate(user)


@app.get("/v1/organizations", response_model=list[OrganizationOut])
async def list_organizations(
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    return [
        OrganizationOut.model_validate(org)
        for org, _role in await user_memberships(db, user.id)
    ]


async def scoped_server(
    db: AsyncSession,
    user: User,
    server_id: UUID,
    request: Request,
):
    org = await current_org(request, db, user)
    server = await db.get(Server, server_id)
    if not server or server.organization_id != org.id:
        raise HTTPException(status_code=404, detail="server not found")
    return org, server


async def scoped_write_server(
    db: AsyncSession,
    user: User,
    server_id: UUID,
    request: Request,
):
    org, role = await current_membership(request, db, user)
    if role not in ROLE_WRITE:
        raise HTTPException(status_code=403, detail="write access required")
    server = await db.get(Server, server_id)
    if not server or server.organization_id != org.id:
        raise HTTPException(status_code=404, detail="server not found")
    return org, server


@app.get("/v1/servers", response_model=list[ServerOut])
async def list_servers(
    response: Response,
    request: Request,
    include_metrics: bool = Query(default=True),
    limit: int = Query(default=100, ge=1, le=500),
    cursor: str | None = Query(default=None),
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    limit = normalize_limit(limit)
    org = await current_org(request, db, user)
    parsed = parse_cursor(cursor, "servers")

    base = select(Server).where(Server.organization_id == org.id)
    if parsed:
        try:
            cursor_id = UUID(parsed.item_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid pagination cursor") from exc
        base = base.where(
            or_(
                Server.updated_at < parsed.timestamp,
                and_(Server.updated_at == parsed.timestamp, Server.id < cursor_id),
            )
        )

    statement = base.order_by(desc(Server.updated_at), desc(Server.id)).limit(limit + 1)
    if include_metrics:
        rows = list((await db.execute(statement)).scalars().all())
        page_rows = rows[:limit]
        items = [server_output(row, datetime.now(timezone.utc), True) for row in page_rows]
    else:
        statement = (
            select(
                Server.id,
                Server.name,
                Server.hostname,
                Server.public_ipv4,
                Server.public_ipv6,
                Server.agent_version,
                Server.status,
                Server.last_seen_at,
                Server.updated_at,
            )
            .where(Server.organization_id == org.id)
            .order_by(desc(Server.updated_at), desc(Server.id))
            .limit(limit + 1)
        )
        if parsed:
            try:
                cursor_id = UUID(parsed.item_id)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="invalid pagination cursor") from exc
            statement = statement.where(
                or_(
                    Server.updated_at < parsed.timestamp,
                    and_(Server.updated_at == parsed.timestamp, Server.id < cursor_id),
                )
            )
        rows = list((await db.execute(statement)).all())
        page_rows = rows[:limit]
        now = datetime.now(timezone.utc)
        items = [
            ServerOut(
                id=row.id,
                name=row.name,
                hostname=row.hostname,
                public_ipv4=row.public_ipv4,
                public_ipv6=row.public_ipv6,
                agent_version=row.agent_version,
                status=effective_status_value(row.status, row.last_seen_at, now),
                metrics={},
                last_seen_at=row.last_seen_at,
            )
            for row in page_rows
        ]

    next_cursor = None
    if len(rows) > limit and page_rows:
        last = page_rows[-1]
        next_cursor = encode_cursor(
            kind="servers",
            timestamp=last.updated_at,
            item_id=str(last.id),
            secret=cursor_secret(),
        )
    set_page_headers(response, limit, next_cursor)
    return items


@app.get("/v1/servers/{server_id}", response_model=ServerOut)
async def get_server(
    server_id: UUID,
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    _, server = await scoped_server(db, user, server_id, request)
    return server_output(server, datetime.now(timezone.utc), True)


@app.post("/v1/servers")
async def create_server(
    body: ServerCreate,
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    org, role = await current_membership(request, db, user)
    if role not in ROLE_WRITE:
        raise HTTPException(status_code=403, detail="write access required")

    server = Server(
        organization_id=org.id,
        name=body.name,
        hostname=body.hostname,
        public_ipv4=body.public_ipv4,
        public_ipv6=body.public_ipv6,
        status="provisioning",
    )
    db.add(server)
    await db.flush()

    raw = new_node_token()
    db.add(ServerToken(server_id=server.id, token_hash=token_hash(raw)))
    await record_event(
        db,
        org.id,
        user.id,
        server.id,
        "server.created",
        {"name": server.name},
    )
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail="server name already exists in this organization",
        )
    return {"server": server_output(server, datetime.now(timezone.utc)), "node_token": raw}


async def authenticated_agent(
    db: AsyncSession,
    server_id: UUID,
    authorization: str | None,
) -> Server:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="agent token required")
    raw = authorization[7:].strip()
    if not raw:
        raise HTTPException(status_code=401, detail="agent token required")

    digest = token_hash(raw)
    server = await db.scalar(
        select(Server)
        .join(ServerToken, ServerToken.server_id == Server.id)
        .where(
            and_(
                Server.id == server_id,
                ServerToken.token_hash == digest,
                ServerToken.revoked_at.is_(None),
            )
        )
        .limit(1)
    )
    if not server:
        raise HTTPException(status_code=401, detail="invalid agent token")
    return server


@app.post("/v1/servers/{server_id}/heartbeat")
async def heartbeat(
    server_id: UUID,
    body: HeartbeatIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    server = await authenticated_agent(
        db, server_id, request.headers.get("Authorization")
    )
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
async def rotate_server_token(
    server_id: UUID,
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    org, server = await scoped_write_server(db, user, server_id, request)
    now = datetime.now(timezone.utc)
    await db.execute(
        update(ServerToken)
        .where(
            and_(
                ServerToken.server_id == server.id,
                ServerToken.revoked_at.is_(None),
            )
        )
        .values(revoked_at=now)
    )
    raw = new_node_token()
    db.add(ServerToken(server_id=server.id, token_hash=token_hash(raw)))
    await record_event(
        db,
        org.id,
        user.id,
        server.id,
        "server.token_rotated",
        {},
    )
    await db.commit()
    return {"node_token": raw}


@app.get("/v1/servers/{server_id}/commands/next", response_model=CommandOut | None)
async def next_command(
    server_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    server = await authenticated_agent(
        db, server_id, request.headers.get("Authorization")
    )
    now = datetime.now(timezone.utc)

    for _ in range(20):
        result = await db.execute(
            select(Command)
            .where(
                and_(
                    Command.server_id == server.id,
                    or_(
                        Command.status == "queued",
                        and_(
                            Command.status.in_({"sent", "running"}),
                            Command.lease_until < now,
                        ),
                    ),
                )
            )
            .order_by(Command.created_at, Command.id)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        cmd = result.scalar_one_or_none()
        if not cmd:
            await db.commit()
            return None

        if cmd.attempt_count >= settings.command_max_attempts:
            cmd.status = "expired"
            cmd.finished_at = now
            cmd.lease_until = None
            continue

        cmd.status = "sent"
        cmd.lease_until = now + timedelta(seconds=settings.command_lease_seconds)
        cmd.attempt_count += 1
        await db.commit()
        return cmd

    await db.commit()
    return None


@app.post(
    "/v1/servers/{server_id}/commands/{command_id}/result",
    response_model=CommandOut,
)
async def command_result(
    server_id: UUID,
    command_id: UUID,
    request: Request,
    result_payload: CommandResult,
    db: AsyncSession = Depends(get_db),
):
    server = await authenticated_agent(
        db, server_id, request.headers.get("Authorization")
    )
    cmd = await db.get(Command, command_id)
    if not cmd or cmd.server_id != server.id:
        raise HTTPException(status_code=404, detail="command not found")

    status_value = result_payload.status
    if cmd.status in {"succeeded", "failed", "cancelled", "expired"}:
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


@app.post(
    "/v1/servers/{server_id}/commands/{command_id}/cancel",
    response_model=CommandOut,
)
async def cancel_command(
    server_id: UUID,
    command_id: UUID,
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    org, server = await scoped_write_server(db, user, server_id, request)
    cmd = await db.get(Command, command_id)
    if not cmd or cmd.organization_id != org.id or cmd.server_id != server.id:
        raise HTTPException(status_code=404, detail="command not found")
    if cmd.status not in {"queued", "sent"}:
        raise HTTPException(status_code=409, detail="command cannot be cancelled")

    cmd.status = "cancelled"
    cmd.finished_at = datetime.now(timezone.utc)
    cmd.lease_until = None
    await record_event(
        db,
        org.id,
        user.id,
        server.id,
        "command.cancelled",
        {"command_id": str(command_id)},
    )
    await db.commit()
    return cmd


@app.post(
    "/v1/servers/{server_id}/commands",
    response_model=CommandOut,
)
async def create_command(
    server_id: UUID,
    body: CommandCreate,
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    org, server = await scoped_write_server(db, user, server_id, request)
    cmd = Command(
        organization_id=org.id,
        server_id=server.id,
        command_type=body.command_type,
        payload=body.payload,
        requested_by=user.id,
        idempotency_key=body.idempotency_key,
    )
    db.add(cmd)
    await record_event(
        db,
        org.id,
        user.id,
        server.id,
        "command.queued",
        {"type": body.command_type},
    )
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        if body.idempotency_key:
            existing = await db.scalar(
                select(Command).where(
                    and_(
                        Command.organization_id == org.id,
                        Command.idempotency_key == body.idempotency_key,
                    )
                )
            )
            if existing:
                return existing
        raise HTTPException(
            status_code=409,
            detail="command creation conflicted with another request",
        )
    return cmd


@app.get(
    "/v1/servers/{server_id}/commands",
    response_model=list[CommandOut],
)
async def list_commands(
    response: Response,
    server_id: UUID,
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    cursor: str | None = Query(default=None),
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    limit = normalize_limit(limit)
    _, server = await scoped_server(db, user, server_id, request)
    parsed = parse_cursor(cursor, "commands")

    statement = select(Command).where(Command.server_id == server.id)
    if parsed:
        try:
            cursor_id = UUID(parsed.item_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid pagination cursor") from exc
        statement = statement.where(
            or_(
                Command.created_at < parsed.timestamp,
                and_(
                    Command.created_at == parsed.timestamp,
                    Command.id < cursor_id,
                ),
            )
        )
    statement = statement.order_by(
        desc(Command.created_at), desc(Command.id)
    ).limit(limit + 1)

    rows = list((await db.execute(statement)).scalars().all())
    items = rows[:limit]
    next_cursor = None
    if len(rows) > limit and items:
        last = items[-1]
        next_cursor = encode_cursor(
            kind="commands",
            timestamp=last.created_at,
            item_id=str(last.id),
            secret=cursor_secret(),
        )
    set_page_headers(response, limit, next_cursor)
    return items


@app.get("/v1/events")
async def events(
    response: Response,
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    cursor: str | None = Query(default=None),
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    limit = normalize_limit(limit)
    org = await current_org(request, db, user)
    parsed = parse_cursor(cursor, "events")

    statement = select(AuditEvent).where(AuditEvent.organization_id == org.id)
    if parsed:
        try:
            cursor_id = int(parsed.item_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid pagination cursor") from exc
        statement = statement.where(
            or_(
                AuditEvent.created_at < parsed.timestamp,
                and_(
                    AuditEvent.created_at == parsed.timestamp,
                    AuditEvent.id < cursor_id,
                ),
            )
        )

    statement = statement.order_by(
        desc(AuditEvent.created_at), desc(AuditEvent.id)
    ).limit(limit + 1)

    rows = list((await db.execute(statement)).scalars().all())
    items = [
        {
            "id": row.id,
            "event_type": row.event_type,
            "server_id": str(row.server_id) if row.server_id else None,
            "metadata": row.metadata,
            "created_at": row.created_at,
        }
        for row in rows[:limit]
    ]

    next_cursor = None
    if len(rows) > limit and items:
        last = rows[limit - 1]
        next_cursor = encode_cursor(
            kind="events",
            timestamp=last.created_at,
            item_id=str(last.id),
            secret=cursor_secret(),
        )
    set_page_headers(response, limit, next_cursor)
    return items


@app.get("/")
async def index():
    return FileResponse("/app/web/index.html")


@app.get("/readyz")
async def readyz():
    try:
        async with engine.connect() as conn:
            await conn.exec_driver_sql("select 1")
        return {"status": "ready", "service": "control-plane"}
    except Exception:
        raise HTTPException(status_code=503, detail="database unavailable")
