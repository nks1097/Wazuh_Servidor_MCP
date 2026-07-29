#!/usr/bin/env python3
"""
Wazuh MCP Server - Complete MCP-Compliant Remote Server
Full compliance with Model Context Protocol 2025-11-25 specification
Production-ready with Streamable HTTP and legacy SSE transport, authentication, and monitoring
"""

import asyncio
import json
import logging
import os
import re as _re
import threading
import time
import uuid
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, ValidationError

from wazuh_mcp_server import __version__
from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.api.wazuh_indexer import IndexerNotConfiguredError
from wazuh_mcp_server.auth import create_access_token
from wazuh_mcp_server.config import WazuhConfig, get_config
from wazuh_mcp_server.monitoring import ACTIVE_CONNECTIONS, setup_monitoring_middleware
from wazuh_mcp_server.resilience import GracefulShutdown
from wazuh_mcp_server.security import (
    RateLimiter,
    ToolValidationError,
    security_middleware,
    validate_active_response_command,
    validate_agent_id,
    validate_agent_status,
    validate_boolean,
    validate_compliance_framework,
    validate_file_path,
    validate_indicator,
    validate_indicator_type,
    validate_input,
    validate_ip_address,
    validate_limit,
    validate_query,
    validate_report_type,
    validate_rule_id,
    validate_severity,
    validate_time_range,
    validate_timestamp,
    validate_username,
)
from wazuh_mcp_server.session_store import SessionStore, create_session_store

# MCP Protocol Version Support
# Latest: 2025-11-25, also supports backwards compatibility with older versions
MCP_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]

# Production Constants
SESSION_TIMEOUT_MINUTES = 30
RATE_LIMIT_REQUESTS = 100
RATE_LIMIT_WINDOW_SECONDS = 60
CORS_MAX_AGE_SECONDS = 600
DEFAULT_QUERY_LIMIT = 100
MAX_QUERY_LIMIT = 1000

logger = logging.getLogger(__name__)

# OAuth manager (initialized on startup if needed)
_oauth_manager = None


async def verify_authentication(authorization: Optional[str], config) -> Optional[Any]:
    """
    Verify authentication based on configured auth mode.

    Returns AuthToken if authenticated (None for authless mode).
    Raises HTTPException if authentication fails.
    Supports: authless (none), bearer token, and OAuth modes.
    """
    from wazuh_mcp_server.auth import AuthToken

    # Authless mode - no authentication required
    if config.is_authless:
        # Return a synthetic token with scopes based on AUTHLESS_ALLOW_WRITE
        allow_write = os.getenv("AUTHLESS_ALLOW_WRITE", "false").lower() in ("true", "1", "yes")
        scopes = ["wazuh:read", "wazuh:write"] if allow_write else ["wazuh:read"]
        return AuthToken(
            token="authless",
            api_key_id="authless",
            created_at=datetime.now(timezone.utc),
            scopes=scopes,
        )

    # Authentication required
    if not authorization:
        raise HTTPException(
            status_code=401, detail="Authorization header required", headers={"WWW-Authenticate": "Bearer"}
        )

    # OAuth mode
    if config.is_oauth:
        global _oauth_manager
        if _oauth_manager:
            token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else authorization
            token_obj = _oauth_manager.validate_access_token(token)
            if token_obj:
                # Return AuthToken with OAuth scopes
                scope_str = getattr(token_obj, "scope", "wazuh:read wazuh:write")
                scopes = scope_str.split() if scope_str else ["wazuh:read", "wazuh:write"]
                return AuthToken(
                    token=token,
                    api_key_id="oauth",
                    created_at=datetime.now(timezone.utc),
                    scopes=scopes,
                )
        raise HTTPException(
            status_code=401, detail="Invalid or expired OAuth token", headers={"WWW-Authenticate": "Bearer"}
        )

    # Bearer token mode (default)
    try:
        from wazuh_mcp_server.auth import verify_bearer_token

        return await verify_bearer_token(authorization)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e), headers={"WWW-Authenticate": "Bearer"})


# MCP Protocol Models
class MCPRequest(BaseModel):
    """MCP JSON-RPC 2.0 Request."""

    jsonrpc: str = Field(default="2.0", description="JSON-RPC version")
    id: Optional[Union[str, int]] = Field(default=None, description="Request ID")
    method: str = Field(description="Method name")
    params: Optional[Dict[str, Any]] = Field(default=None, description="Method parameters")


class MCPResponse(BaseModel):
    """
    MCP JSON-RPC 2.0 Response.

    Compliant with JSON-RPC 2.0 specification:
    - On success: includes 'result', excludes 'error'
    - On error: includes 'error', excludes 'result'
    """

    jsonrpc: str = Field(default="2.0", description="JSON-RPC version")
    id: Optional[Union[str, int]] = Field(default=None, description="Request ID")
    result: Optional[Any] = Field(default=None, description="Result data")
    error: Optional[Dict[str, Any]] = Field(default=None, description="Error object")

    def model_dump(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Override model_dump() to comply with JSON-RPC 2.0 specification.

        Per JSON-RPC 2.0 spec:
        - "result" and "error" MUST NOT both exist in the same response
        - On success: include 'result', exclude 'error'
        - On error: include 'error', exclude 'result'
        """
        d = super().model_dump(*args, **kwargs)

        # Determine which field was explicitly set.
        # error takes precedence: if error is set, this is an error response.
        if d.get("error") is not None:
            d.pop("result", None)
        else:
            # Success response: result may be any JSON value including None, 0, "", [].
            # Remove the error field since it's not an error response.
            d.pop("error", None)

        return d

    def dict(self, *args, **kwargs) -> Dict[str, Any]:
        """Backwards-compatible wrapper for model_dump()."""
        return self.model_dump(*args, **kwargs)


class MCPError(BaseModel):
    """MCP JSON-RPC 2.0 Error object."""

    code: int = Field(description="Error code")
    message: str = Field(description="Error message")
    data: Optional[Any] = Field(default=None, description="Additional error data")


class MCPSession:
    """MCP Session Management for Remote MCP Server."""

    def __init__(self, session_id: str, origin: Optional[str] = None):
        self.session_id = session_id
        self.origin = origin
        self.created_at = datetime.now(timezone.utc)
        self.last_activity = self.created_at
        self.capabilities = {}
        self.client_info = {}
        self.authenticated = False

    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = datetime.now(timezone.utc)

    def is_expired(self, timeout_minutes: int = SESSION_TIMEOUT_MINUTES) -> bool:
        """Check if session is expired."""
        timeout = timedelta(minutes=timeout_minutes)
        return datetime.now(timezone.utc) - self.last_activity > timeout

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary."""
        return {
            "session_id": self.session_id,
            "origin": self.origin,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "capabilities": self.capabilities,
            "client_info": self.client_info,
            "authenticated": self.authenticated,
        }


# Session management with pluggable backend (serverless-ready)
class SessionManager:
    """
    Session manager with pluggable storage backend.
    Supports both in-memory (default) and Redis (serverless-ready) backends.
    """

    def __init__(self, store: SessionStore):
        self._store = store
        self._lock = threading.RLock()  # For synchronous operations
        logger.info(f"SessionManager initialized with {type(store).__name__}")

    def _session_from_dict(self, data: Dict[str, Any]) -> MCPSession:
        """Reconstruct MCPSession from dictionary."""
        session = MCPSession(data["session_id"], data.get("origin"))
        session.created_at = datetime.fromisoformat(data["created_at"].replace("Z", "+00:00"))
        session.last_activity = datetime.fromisoformat(data["last_activity"].replace("Z", "+00:00"))
        session.capabilities = data.get("capabilities", {})
        session.client_info = data.get("client_info", {})
        session.authenticated = data.get("authenticated", False)
        return session

    async def get(self, session_id: str) -> Optional[MCPSession]:
        """Get session by ID."""
        data = await self._store.get(session_id)
        if data:
            return self._session_from_dict(data)
        return None

    async def set(self, session_id: str, session: MCPSession) -> bool:
        """Store session."""
        return await self._store.set(session_id, session.to_dict())

    def _run_sync(self, coro):
        """Run coroutine synchronously, handling existing event loop safely."""
        try:
            asyncio.get_running_loop()
            # If we get here, there's a running loop - this is not safe
            raise RuntimeError(
                "Synchronous SessionManager methods cannot be called from async context. "
                "Use async methods like 'await sessions.get()' instead."
            )
        except RuntimeError as e:
            # Re-raise if this is our own "cannot be called from async" error
            if "Synchronous SessionManager" in str(e):
                raise
            # No running loop - safe to create one
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(coro)
            finally:
                loop.close()

    def __getitem__(self, session_id: str) -> MCPSession:
        """Synchronous dict-like access (blocks). Not for use in async context."""
        session = self._run_sync(self.get(session_id))
        if session is None:
            raise KeyError(f"Session {session_id} not found")
        return session

    def __setitem__(self, session_id: str, session: MCPSession) -> None:
        """Synchronous dict-like access (blocks). Not for use in async context."""
        self._run_sync(self.set(session_id, session))

    def __delitem__(self, session_id: str) -> None:
        """Synchronous delete (blocks). Not for use in async context."""
        self._run_sync(self.remove(session_id))

    def __contains__(self, session_id: str) -> bool:
        """Check if session exists (synchronous for use with 'in' operator)."""
        return self._run_sync(self._store.exists(session_id))

    async def remove(self, session_id: str) -> bool:
        """Remove session by ID."""
        return await self._store.delete(session_id)

    def pop(self, session_id: str, default=None) -> Optional[MCPSession]:
        """Remove and return session (synchronous, blocks). Not for use in async context."""

        async def _pop():
            session = await self.get(session_id)
            if session:
                await self.remove(session_id)
                return session
            return default

        return self._run_sync(_pop())

    async def clear(self) -> bool:
        """Clear all sessions."""
        return await self._store.clear()

    def values(self) -> List[MCPSession]:
        """Get all session values (synchronous, blocks). Not for use in async context."""
        sessions_dict = self._run_sync(self.get_all())
        return list(sessions_dict.values())

    def keys(self) -> List[str]:
        """Get all session keys (synchronous, blocks). Not for use in async context."""
        sessions_dict = self._run_sync(self.get_all())
        return list(sessions_dict.keys())

    async def get_all(self) -> Dict[str, MCPSession]:
        """Get all sessions as dictionary."""
        data_dict = await self._store.get_all()
        return {sid: self._session_from_dict(data) for sid, data in data_dict.items()}

    async def cleanup_expired(self, timeout_minutes: int = 30) -> int:
        """Remove expired sessions and return count."""
        return await self._store.cleanup_expired(timeout_minutes=timeout_minutes)


# Initialize session manager with pluggable backend
# Will use Redis if REDIS_URL is set, otherwise in-memory
_session_store = create_session_store()
sessions = SessionManager(_session_store)

# Track last session cleanup time (run at most every 60 seconds, not every request)
_last_session_cleanup: float = 0.0


async def get_or_create_session(session_id: Optional[str], origin: Optional[str]) -> MCPSession:
    """Get existing session or create new one."""
    global _last_session_cleanup

    if session_id:
        existing_session = await sessions.get(session_id)
        if existing_session:
            existing_session.update_activity()
            await sessions.set(session_id, existing_session)
            return existing_session

    # Always generate server-side session IDs to prevent session fixation attacks.
    # Client-provided session IDs are only used to look up existing sessions above.
    new_session_id = str(uuid.uuid4())
    session = MCPSession(new_session_id, origin)
    await sessions.set(new_session_id, session)

    # Cleanup expired sessions periodically (at most every 60 seconds)
    now = time.time()
    if now - _last_session_cleanup > 60:
        _last_session_cleanup = now
        try:
            expired_count = await sessions.cleanup_expired()
            if expired_count > 0:
                logger.debug(f"Cleaned up {expired_count} expired sessions")
                # Sync _initialized_sessions with active sessions
                active = await sessions.get_all()
                stale_keys = [k for k in _initialized_sessions if k not in active]
                for k in stale_keys:
                    _initialized_sessions.pop(k, None)
        except Exception as e:
            logger.error(f"Session cleanup error: {e}")

    return session


# Lifespan context manager for startup/shutdown events (modern FastAPI pattern)
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle with proper startup and shutdown handling."""
    global _oauth_manager

    # === STARTUP ===
    # Attach log sanitization filter to prevent credential leakage
    from wazuh_mcp_server.security import SanitizingLogFilter

    logging.getLogger().addFilter(SanitizingLogFilter())

    logger.info(f"Wazuh MCP Server v{__version__} starting up...")
    logger.info(f"📡 MCP Protocol: {MCP_PROTOCOL_VERSION}")
    logger.info(f"🔗 Wazuh Host: {get_config().WAZUH_HOST}")
    logger.info(f"🌐 CORS Origins: {get_config().ALLOWED_ORIGINS}")
    logger.info(f"🔐 Auth Mode: {get_config().AUTH_MODE}")

    # Log Indexer configuration status
    cfg = get_config()
    if cfg.WAZUH_INDEXER_HOST:
        logger.info(f"📊 Wazuh Indexer: {cfg.WAZUH_INDEXER_HOST}:{cfg.WAZUH_INDEXER_PORT}")
    else:
        logger.warning("⚠️  Wazuh Indexer not configured. Vulnerability tools require Wazuh 4.8.0+")
        logger.warning("   Set WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS to enable.")

    # Initialize OAuth if enabled
    if cfg.is_oauth:
        try:
            from wazuh_mcp_server.oauth import create_oauth_router, init_oauth_manager

            _oauth_manager = init_oauth_manager(cfg)
            oauth_router = create_oauth_router(_oauth_manager)
            app.include_router(oauth_router)
            logger.info("✅ OAuth 2.0 with DCR initialized")
            logger.info("   OAuth endpoints: /oauth/authorize, /oauth/token, /oauth/register")
            logger.info("   Discovery: /.well-known/oauth-authorization-server")
        except Exception as e:
            logger.error(f"❌ OAuth initialization failed: {e}")

    # Log auth mode status
    if cfg.is_authless:
        logger.warning("⚠️  Running in AUTHLESS mode - no authentication required!")
    elif cfg.is_bearer:
        logger.info("🔐 Bearer token authentication enabled")
        # Display auto-generated API key if not configured via environment
        if not os.getenv("MCP_API_KEY"):
            from wazuh_mcp_server.auth import auth_manager

            default_key = auth_manager.get_default_api_key()
            if default_key:
                logger.info("=" * 60)
                logger.info("🔑 AUTO-GENERATED API KEY (save this for client auth):")
                logger.info(f"   {default_key}")
                logger.info("   Set MCP_API_KEY environment variable in production")
                logger.info("=" * 60)

    # Start background session cleanup task (runs every 5 minutes regardless of traffic)
    async def _background_session_cleanup():
        while True:
            await asyncio.sleep(300)
            try:
                expired = await sessions.cleanup_expired()
                if expired > 0:
                    logger.debug(f"Background cleanup: removed {expired} expired sessions")
                    active = await sessions.get_all()
                    stale = [k for k in _initialized_sessions if k not in active]
                    for k in stale:
                        _initialized_sessions.pop(k, None)
            except Exception as e:
                logger.error(f"Background session cleanup error: {e}")

    _cleanup_task = asyncio.create_task(_background_session_cleanup())

    # Initialize Wazuh client (will be available after yield)
    logger.info("✅ Server startup complete with high availability features enabled")

    yield  # Server is running

    # === SHUTDOWN ===
    logger.info("🛑 Wazuh MCP Server initiating graceful shutdown...")

    # Cancel background session cleanup
    _cleanup_task.cancel()
    try:
        await _cleanup_task
    except asyncio.CancelledError:
        pass

    try:
        # Initiate graceful shutdown (waits for active connections)
        await shutdown_manager.initiate_shutdown()

        # Clear and cleanup auth manager
        from wazuh_mcp_server.auth import auth_manager

        auth_manager.cleanup_expired()
        auth_manager.tokens.clear()
        logger.info("Authentication tokens cleared")

        # Clear sessions with proper cleanup
        await sessions.clear()
        # Close session store backend (e.g., Redis connection)
        if hasattr(sessions._store, "close"):
            await sessions._store.close()
        logger.info("Sessions cleared")

        # Close Wazuh client to release HTTP connections
        if wazuh_client and hasattr(wazuh_client, "close"):
            await wazuh_client.close()
            logger.info("Wazuh client closed")

        # Cleanup rate limiter
        if hasattr(rate_limiter, "cleanup"):
            rate_limiter.cleanup()

        # Close connection pools
        from wazuh_mcp_server.security import connection_pool_manager

        await connection_pool_manager.close_all()
        logger.info("Connection pools closed")

        # Force garbage collection
        import gc

        gc.collect()
        logger.info("Garbage collection completed")

    except Exception as e:
        logger.error(f"Error during shutdown: {e}")
    finally:
        logger.info("✅ Graceful shutdown completed")


# Initialize FastAPI app for MCP compliance
app = FastAPI(
    title="Wazuh MCP Server",
    description="MCP-compliant remote server for Wazuh SIEM integration. Supports Streamable HTTP, SSE, OAuth, and authless modes.",
    version=__version__,
    docs_url="/docs",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# Get configuration
config = get_config()

# Create Wazuh configuration from server config
wazuh_config = WazuhConfig(
    wazuh_host=config.WAZUH_HOST,
    wazuh_user=config.WAZUH_USER,
    wazuh_pass=config.WAZUH_PASS,
    wazuh_port=config.WAZUH_PORT,
    verify_ssl=config.WAZUH_VERIFY_SSL,
    # Wazuh Indexer settings (required for vulnerability tools in Wazuh 4.8.0+)
    wazuh_indexer_host=config.WAZUH_INDEXER_HOST if config.WAZUH_INDEXER_HOST else None,
    wazuh_indexer_port=config.WAZUH_INDEXER_PORT,
    wazuh_indexer_user=config.WAZUH_INDEXER_USER if config.WAZUH_INDEXER_USER else None,
    wazuh_indexer_pass=config.WAZUH_INDEXER_PASS if config.WAZUH_INDEXER_PASS else None,
)

# Initialize Wazuh client
wazuh_client = WazuhClient(wazuh_config)


async def get_wazuh_client() -> WazuhClient:
    """Get the global Wazuh client instance.

    Used by monitoring health checks to access client state.
    """
    return wazuh_client


# Initialize rate limiter
rate_limiter = RateLimiter(max_requests=RATE_LIMIT_REQUESTS, window_seconds=RATE_LIMIT_WINDOW_SECONDS)

# Initialize graceful shutdown manager
shutdown_manager = GracefulShutdown()
logger.info("Graceful shutdown manager initialized")


# CORS middleware for remote access with security
def validate_cors_origins(origins_config: str) -> List[str]:
    """Validate and parse CORS origins configuration."""
    if not origins_config or origins_config.strip() == "*":
        # Only allow wildcard in development
        if os.getenv("ENVIRONMENT") == "development":
            return ["*"]
        else:
            # In production, default to common Claude origins
            return ["https://claude.ai", "https://claude.anthropic.com"]

    origins = []
    for origin in origins_config.split(","):
        origin = origin.strip()
        # Validate origin format
        if origin.startswith(("http://", "https://")) or origin == "*":
            # Parse and validate URL structure
            if origin != "*":
                try:
                    parsed = urlparse(origin)
                    if parsed.netloc:
                        origins.append(origin)
                except ValueError as e:
                    logger.debug(f"Skipping invalid origin '{origin}': {e}")
                    continue
            else:
                origins.append(origin)

    return origins if origins else ["https://claude.ai"]


def validate_origin_header(origin: Optional[str], allowed_origins_config: str) -> None:
    """
    Validate Origin header per MCP 2025-11-25 spec.

    Per spec: "Servers MUST validate the Origin header on all incoming connections
    to prevent DNS rebinding attacks. If the Origin header is present and invalid,
    servers MUST respond with HTTP 403 Forbidden."

    Note: If Origin header is NOT present, that's acceptable (no 403).
    Only reject if Origin IS present but invalid.

    Args:
        origin: The Origin header value (may be None)
        allowed_origins_config: Comma-separated list of allowed origins

    Raises:
        HTTPException: 403 if Origin is present but not in allowed list
    """
    # Per 2025-11-25 spec: only validate if Origin is present
    if not origin:
        return  # No Origin header = acceptable

    # Parse allowed origins
    allowed_origins_list = allowed_origins_config.split(",") if allowed_origins_config else []

    # Check if origin is allowed (exact match only for security)
    for allowed in allowed_origins_list:
        allowed = allowed.strip()
        if allowed == "*":
            return  # Wildcard allows everything
        if allowed == origin:
            return  # Exact match

    # Origin present but not in allowed list - per spec MUST return 403
    raise HTTPException(status_code=403, detail=f"Origin not allowed: {origin}")


# Register monitoring middleware for request tracking and correlation IDs
app.middleware("http")(setup_monitoring_middleware())

# Register security middleware for security headers and request validation
app.middleware("http")(security_middleware)

allowed_origins = validate_cors_origins(config.ALLOWED_ORIGINS)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],  # Added DELETE for session management
    allow_headers=[
        "Accept",
        "Accept-Language",
        "Content-Language",
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "MCP-Protocol-Version",  # MCP protocol version header
        "MCP-Session-Id",  # Session ID header
        "Last-Event-ID",  # SSE reconnection header
    ],  # Specific headers only, no wildcard
    expose_headers=["MCP-Session-Id", "MCP-Protocol-Version", "Content-Type"],
    max_age=CORS_MAX_AGE_SECONDS,
)

# MCP Protocol Error Codes
MCP_ERRORS = {
    "PARSE_ERROR": -32700,
    "INVALID_REQUEST": -32600,
    "METHOD_NOT_FOUND": -32601,
    "INVALID_PARAMS": -32602,
    "INTERNAL_ERROR": -32603,
    "TIMEOUT": -32001,
    "CANCELLED": -32002,
    "RESOURCE_NOT_FOUND": -32003,
}


def create_error_response(
    request_id: Optional[Union[str, int]], code: int, message: str, data: Any = None
) -> MCPResponse:
    """Create MCP error response with correlation ID for tracing."""
    from wazuh_mcp_server.monitoring import get_correlation_id

    # Include correlation ID in error data for request tracing
    error_data = data if data else {}
    if isinstance(error_data, dict):
        error_data = {**error_data, "correlation_id": get_correlation_id()}
    elif data is None:
        error_data = {"correlation_id": get_correlation_id()}
    error = MCPError(code=code, message=message, data=error_data)
    return MCPResponse(id=request_id, error=error.dict())


def create_success_response(request_id: Optional[Union[str, int]], result: Any) -> MCPResponse:
    """Create MCP success response."""
    return MCPResponse(id=request_id, result=result)


def validate_protocol_version(version: Optional[str], strict: bool = False) -> str:
    """
    Validate and normalize MCP protocol version.

    Per MCP 2025-11-25 spec:
    - If no header provided, assume 2025-03-26 for backwards compatibility
    - If invalid/unsupported version, MUST return 400 Bad Request (when strict=True)

    Args:
        version: The protocol version from MCP-Protocol-Version header
        strict: If True, raise HTTPException for invalid versions (2025-11-25 behavior)

    Returns:
        The validated protocol version string
    """
    if not version:
        # Per spec: assume 2025-03-26 if no header provided (backwards compatibility)
        return "2025-03-26"

    if version in SUPPORTED_PROTOCOL_VERSIONS:
        return version

    # Per 2025-11-25 spec: "If the server receives a request with an invalid or
    # unsupported MCP-Protocol-Version, it MUST respond with 400 Bad Request"
    if strict:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported protocol version: {version}. Supported versions: {', '.join(SUPPORTED_PROTOCOL_VERSIONS)}",
        )

    # For backwards compatibility (non-strict mode), try to handle gracefully
    logger.warning(f"Unsupported protocol version {version}, falling back to 2025-03-26")
    return "2025-03-26"


# Track initialized sessions (OrderedDict for O(1) eviction of oldest entries)
_initialized_sessions: OrderedDict[str, bool] = OrderedDict()

# Current log level for logging/setLevel
_current_log_level: str = "info"


# Batch request size limit to prevent resource exhaustion
MAX_BATCH_SIZE = 100

# MCP Protocol Handlers


# Patterns to redact from output text (credentials, tokens, keys in log lines)
_OUTPUT_REDACT_PATTERNS = [
    _re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+'),
    _re.compile(r'(?i)(api[_-]?key|secret|token)\s*[=:]\s*\S+'),
    _re.compile(r'(?i)Authorization:\s*.+'),
]


def _sanitize_output_text(text: str) -> str:
    """Redact credentials/tokens from log text before returning to MCP clients."""
    for pattern in _OUTPUT_REDACT_PATTERNS:
        text = pattern.sub(lambda m: m.group().split("=")[0] + "=[REDACTED]" if "=" in m.group()
                           else m.group().split(":")[0] + ": [REDACTED]", text)
    return text


def _compact_alert(alert: dict) -> dict:
    """Strip a raw Wazuh alert to essential fields for MCP output."""
    compact = {}
    if "timestamp" in alert:
        compact["timestamp"] = alert["timestamp"]
    agent = alert.get("agent", {})
    if agent:
        compact["agent"] = {"id": agent.get("id", ""), "name": agent.get("name", "")}
    rule = alert.get("rule", {})
    if rule:
        compact["rule"] = {
            "id": rule.get("id", ""),
            "level": rule.get("level", 0),
            "description": rule.get("description", ""),
            "groups": rule.get("groups", []),
        }
        if rule.get("mitre"):
            compact["rule"]["mitre"] = rule["mitre"]
    src = alert.get("data", {})
    if src.get("srcip"):
        compact["srcip"] = src["srcip"]
    if src.get("dstip"):
        compact["dstip"] = src["dstip"]
    if alert.get("syscheck"):
        sc = alert["syscheck"]
        compact["syscheck"] = {"path": sc.get("path", ""), "event": sc.get("event", "")}
    if alert.get("full_log"):
        log = str(alert["full_log"])
        log = (log[:300] + "...") if len(log) > 300 else log
        compact["full_log"] = _sanitize_output_text(log)
    return compact


def _compact_alerts_result(result: dict) -> dict:
    """Apply compaction to a standard alerts result dict."""
    data = result.get("data", {})
    items = data.get("affected_items", [])
    data["affected_items"] = [_compact_alert(a) for a in items]
    return result


def _add_truncation_warning(result: dict, requested_limit: int) -> dict:
    """Add a warning if results hit the requested limit (likely truncated)."""
    data = result.get("data", {})
    items = data.get("affected_items", [])
    total = data.get("total_affected_items", len(items))
    if total >= requested_limit:
        result["_warning"] = (
            f"Results may be truncated ({total} items returned, limit was {requested_limit}). "
            f"Use more specific filters (time_range, agent_id, rule_id, level) or increase limit for complete results."
        )
    return result


def _compact_vulnerability(vuln: dict) -> dict:
    """Strip a raw Wazuh vulnerability to essential fields for MCP output."""
    compact = {}
    for key in ("id", "severity"):
        if key in vuln:
            compact[key] = vuln[key]
    if "id" in vuln:
        compact["cve"] = vuln["id"]
    if vuln.get("description"):
        desc = str(vuln["description"])
        compact["description"] = (desc[:120] + "...") if len(desc) > 120 else desc
    if "reference" in vuln:
        compact["reference"] = vuln["reference"]
    if "published_at" in vuln:
        compact["published_at"] = vuln["published_at"]
    pkg = vuln.get("package", {})
    if pkg:
        compact["package"] = {"name": pkg.get("name", ""), "version": pkg.get("version", "")}
    agent = vuln.get("agent", {})
    if agent:
        compact["agent"] = {"id": agent.get("id", ""), "name": agent.get("name", "")}
    return compact


def _compact_vulns_result(result: dict) -> dict:
    """Apply compaction to a standard vulnerabilities result dict."""
    data = result.get("data", {})
    items = data.get("affected_items", [])
    if items:
        data["affected_items"] = [_compact_vulnerability(v) for v in items]
    return result


async def handle_initialize(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """Handle MCP initialize method per MCP specification."""
    client_protocol_version = params.get("protocolVersion", "2025-03-26")
    capabilities = params.get("capabilities", {})
    client_info = params.get("clientInfo", {})

    # Store client information
    session.capabilities = capabilities
    session.client_info = client_info

    # Protocol version negotiation per MCP spec
    # Server should respond with a version it supports
    if client_protocol_version in SUPPORTED_PROTOCOL_VERSIONS:
        negotiated_version = client_protocol_version
    else:
        # Default to latest supported version
        negotiated_version = MCP_PROTOCOL_VERSION

    # Server capabilities - only declare what we actually implement
    server_capabilities = {
        "logging": {},
        "prompts": {"listChanged": True},
        "resources": {"subscribe": False, "listChanged": True},  # Not fully implemented yet
        "tools": {"listChanged": True},
    }

    # Server information
    server_info = {
        "name": "Wazuh Servidor MCP",
        "version": __version__,
        "vendor": "Nks1097",
        "description": "MCP-compliant remote server for Wazuh SIEM integration",
    }

    # Mark session as awaiting initialized notification (cap to prevent unbounded growth)
    if len(_initialized_sessions) > 10000:
        # Evict oldest entries in O(1) per removal
        for _ in range(len(_initialized_sessions) - 5000):
            _initialized_sessions.popitem(last=False)
    _initialized_sessions[session.session_id] = False

    return {
        "protocolVersion": negotiated_version,
        "capabilities": server_capabilities,
        "serverInfo": server_info,
        "instructions": "Connected to Wazuh MCP Server. Use available tools for security operations.",
    }


async def handle_initialized_notification(params: Dict[str, Any], session: MCPSession) -> None:
    """Handle notifications/initialized - marks session as fully initialized."""
    _initialized_sessions[session.session_id] = True
    logger.info(f"Session {session.session_id} fully initialized")


async def handle_ping(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle ping method per MCP specification.
    MUST respond immediately with empty result.
    """
    return {}


async def handle_logging_set_level(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle logging/setLevel method per MCP specification.
    Sets the minimum log level for server log notifications.
    """
    global _current_log_level
    level = params.get("level", "info")

    valid_levels = ["debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"]
    if level.lower() not in valid_levels:
        raise ValueError(f"Invalid log level: {level}. Must be one of: {', '.join(valid_levels)}")

    _current_log_level = level.lower()
    logger.info(f"Log level set to: {_current_log_level}")

    return {}


async def handle_prompts_list(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle prompts/list method per MCP specification.
    Returns list of available prompts with pagination support.
    """
    _cursor = params.get("cursor")  # Reserved for future pagination

    # Wazuh security prompts
    prompts = [
        {
            "name": "security_investigation",
            "description": "Investigate a security incident using Wazuh data",
            "arguments": [
                {
                    "name": "incident_type",
                    "description": "Type of incident to investigate (e.g., malware, intrusion, data_breach)",
                    "required": True,
                },
                {
                    "name": "time_range",
                    "description": "Time range for investigation (e.g., 1h, 24h, 7d)",
                    "required": False,
                },
            ],
        },
        {
            "name": "threat_hunt",
            "description": "Perform proactive threat hunting across Wazuh agents",
            "arguments": [
                {"name": "hunt_hypothesis", "description": "The threat hypothesis to investigate", "required": True},
                {
                    "name": "agent_scope",
                    "description": "Scope of agents to hunt (all, critical, specific)",
                    "required": False,
                },
            ],
        },
        {
            "name": "compliance_audit",
            "description": "Generate compliance audit report for a specific framework",
            "arguments": [
                {
                    "name": "framework",
                    "description": "Compliance framework (PCI-DSS, HIPAA, SOX, GDPR, NIST)",
                    "required": True,
                },
                {
                    "name": "include_remediation",
                    "description": "Include remediation recommendations",
                    "required": False,
                },
            ],
        },
        {
            "name": "vulnerability_assessment",
            "description": "Assess vulnerabilities across the environment",
            "arguments": [
                {
                    "name": "severity_threshold",
                    "description": "Minimum severity to include (low, medium, high, critical)",
                    "required": False,
                },
                {"name": "agent_id", "description": "Specific agent to assess (optional)", "required": False},
            ],
        },
    ]

    # Simple pagination (no cursor means start from beginning)
    # In production, implement proper cursor-based pagination
    return {"prompts": prompts}  # No more results


async def handle_prompts_get(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle prompts/get method per MCP specification.
    Returns prompt content with substituted arguments.
    """
    name = params.get("name")
    arguments = params.get("arguments", {})

    if not name:
        raise ValueError("Prompt name is required")

    # Prompt templates
    prompt_templates = {
        "security_investigation": {
            "description": "Security incident investigation workflow",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"Investigate a {arguments.get('incident_type', 'security')} incident. "
                        f"Time range: {arguments.get('time_range', '24h')}. "
                        f"Steps:\n"
                        f"1. Use get_wazuh_alerts to retrieve relevant alerts\n"
                        f"2. Use analyze_alert_patterns to identify patterns\n"
                        f"3. Use search_security_events to find related events\n"
                        f"4. Use check_agent_health for affected agents\n"
                        f"5. Use perform_risk_assessment to evaluate impact",
                    },
                }
            ],
        },
        "threat_hunt": {
            "description": "Proactive threat hunting workflow",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"Hunt for threats based on hypothesis: {arguments.get('hunt_hypothesis', 'suspicious activity')}. "
                        f"Agent scope: {arguments.get('agent_scope', 'all')}. "
                        f"Workflow:\n"
                        f"1. Use get_wazuh_agents to identify target agents\n"
                        f"2. Use search_security_events with relevant patterns\n"
                        f"3. Use analyze_security_threat for any indicators found\n"
                        f"4. Use check_ioc_reputation for suspicious IPs/domains\n"
                        f"5. Use generate_security_report to document findings",
                    },
                }
            ],
        },
        "compliance_audit": {
            "description": "Compliance audit workflow",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"Perform {arguments.get('framework', 'PCI-DSS')} compliance audit. "
                        f"Include remediation: {arguments.get('include_remediation', 'true')}. "
                        f"Steps:\n"
                        f"1. Use run_compliance_check with the specified framework\n"
                        f"2. Use get_wazuh_agents to assess agent coverage\n"
                        f"3. Use get_wazuh_vulnerabilities to identify security gaps\n"
                        f"4. Use generate_security_report for compliance documentation",
                    },
                }
            ],
        },
        "vulnerability_assessment": {
            "description": "Vulnerability assessment workflow",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"Assess vulnerabilities with severity >= {arguments.get('severity_threshold', 'medium')}. "
                        f"Agent: {arguments.get('agent_id', 'all')}. "
                        f"Workflow:\n"
                        f"1. Use get_wazuh_vulnerabilities to retrieve vulnerability data\n"
                        f"2. Use get_wazuh_critical_vulnerabilities for highest priority items\n"
                        f"3. Use get_wazuh_vulnerability_summary for statistics\n"
                        f"4. Use perform_risk_assessment to evaluate overall risk",
                    },
                }
            ],
        },
    }

    if name not in prompt_templates:
        raise ValueError(f"Unknown prompt: {name}")

    return prompt_templates[name]


async def handle_resources_list(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle resources/list method per MCP specification.
    Returns list of available resources with pagination support.
    """
    _cursor = params.get("cursor")  # Reserved for future pagination

    # Wazuh resources
    resources = [
        {
            "uri": "wazuh://manager/info",
            "name": "Wazuh Manager Information",
            "description": "Current Wazuh manager status and configuration",
            "mimeType": "application/json",
        },
        {
            "uri": "wazuh://agents/summary",
            "name": "Agents Summary",
            "description": "Summary of all Wazuh agents and their status",
            "mimeType": "application/json",
        },
        {
            "uri": "wazuh://alerts/recent",
            "name": "Recent Alerts",
            "description": "Most recent security alerts from Wazuh",
            "mimeType": "application/json",
        },
        {
            "uri": "wazuh://cluster/status",
            "name": "Cluster Status",
            "description": "Wazuh cluster health and node information",
            "mimeType": "application/json",
        },
        {
            "uri": "wazuh://rules/summary",
            "name": "Rules Summary",
            "description": "Summary of active Wazuh detection rules",
            "mimeType": "application/json",
        },
        {
            "uri": "wazuh://vulnerabilities/critical",
            "name": "Critical Vulnerabilities",
            "description": "Critical vulnerabilities from Wazuh Indexer (requires 4.8.0+)",
            "mimeType": "application/json",
        },
    ]

    return {"resources": resources}


async def handle_resources_read(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle resources/read method per MCP specification.
    Returns resource content.
    """
    uri = params.get("uri")

    if not uri:
        raise ValueError("Resource URI is required")

    # Parse Wazuh resource URI
    if not uri.startswith("wazuh://"):
        raise ValueError(f"Invalid resource URI scheme: {uri}. Expected wazuh://")

    resource_path = uri[8:]  # Remove "wazuh://"

    try:
        if resource_path == "manager/info":
            data = await wazuh_client.get_manager_info()
        elif resource_path == "agents/summary":
            data = await wazuh_client.get_running_agents()
        elif resource_path == "alerts/recent":
            data = await wazuh_client.get_alerts(limit=50)
        elif resource_path == "cluster/status":
            data = await wazuh_client.get_cluster_health()
        elif resource_path == "rules/summary":
            data = await wazuh_client.get_rules_summary()
        elif resource_path == "vulnerabilities/critical":
            data = await wazuh_client.get_critical_vulnerabilities(limit=50)
        else:
            raise ValueError(f"Resource not found: {uri}")

        return {"contents": [{"uri": uri, "mimeType": "application/json", "text": json.dumps(data, indent=2, default=str)}]}

    except Exception as e:
        logger.error(f"Error reading resource {uri}: {e}")
        raise ValueError(f"Failed to read resource: {str(e)}")


async def handle_resources_templates_list(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle resources/templates/list method per MCP specification.
    Returns list of resource URI templates.
    """
    templates = [
        {
            "uriTemplate": "wazuh://agents/{agent_id}/info",
            "name": "Agent Information",
            "description": "Detailed information for a specific agent",
            "mimeType": "application/json",
        },
        {
            "uriTemplate": "wazuh://agents/{agent_id}/alerts",
            "name": "Agent Alerts",
            "description": "Recent alerts for a specific agent",
            "mimeType": "application/json",
        },
        {
            "uriTemplate": "wazuh://agents/{agent_id}/vulnerabilities",
            "name": "Agent Vulnerabilities",
            "description": "Vulnerabilities for a specific agent",
            "mimeType": "application/json",
        },
    ]

    return {"resourceTemplates": templates}


async def handle_completion_complete(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle completion/complete method per MCP specification.
    Returns argument completion suggestions.
    """
    ref = params.get("ref", {})
    argument = params.get("argument", {})

    ref_type = ref.get("type")
    ref_name = ref.get("name")
    arg_name = argument.get("name", "")
    arg_value = argument.get("value", "")

    completions = []

    # Provide completions based on context
    if ref_type == "ref/prompt":
        if arg_name == "incident_type":
            completions = ["malware", "intrusion", "data_breach", "ransomware", "phishing", "insider_threat"]
        elif arg_name == "time_range":
            completions = ["1h", "6h", "24h", "7d", "30d"]
        elif arg_name == "framework":
            completions = ["PCI-DSS", "HIPAA", "SOX", "GDPR", "NIST"]
        elif arg_name == "severity_threshold":
            completions = ["low", "medium", "high", "critical"]
        elif arg_name == "agent_scope":
            completions = ["all", "critical", "specific"]

    elif ref_type == "ref/resource":
        if "agent" in ref_name.lower():
            # Could fetch actual agent IDs here
            completions = ["001", "002", "003", "004", "005"]

    # Filter by current value
    if arg_value:
        completions = [c for c in completions if c.lower().startswith(arg_value.lower())]

    return {
        "completion": {
            "values": completions[:100],  # Max 100 per spec
            "total": len(completions),
            "hasMore": len(completions) > 100,
        }
    }


# Tool scope mapping: tools requiring write access (active response, rollback, restart)
# All other tools only require wazuh:read
WRITE_SCOPE_TOOLS = frozenset({
    "resposta_ativa_wazuh",
    "bloquear_ip_wazuh",
    "isolar_host_wazuh",
    "encerrar_processo_wazuh",
    "desabilitar_usuario_wazuh",
    "quarentena_arquivo_wazuh",
    "bloquear_firewall_wazuh",
    "negar_host_wazuh",
    "reiniciar_servico_wazuh",
    "desisolar_host_wazuh",
    "habilitar_usuario_wazuh",
    "restaurar_arquivo_wazuh",
    "permitir_firewall_wazuh",
    "permitir_host_wazuh",
    "gerenciar_grupos_agente",
    "criar_regra_customizada_wazuh",
    "modificar_regra_customizada_wazuh",
    "excluir_regra_customizada_wazuh",
    "criar_decodificador_customizado_wazuh",
    "modificar_decodificador_customizado_wazuh",
    "excluir_decodificador_customizado_wazuh",
})

# Audit logger for destructive operations
audit_logger = logging.getLogger("wazuh_mcp_server.audit")


def _get_tool_scope(tool_name: str) -> str:
    """Get the required scope for a tool."""
    return "wazuh:write" if tool_name in WRITE_SCOPE_TOOLS else "wazuh:read"


async def handle_tools_list(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """Handle tools/list method - Todas as 78 Ferramentas MCP de Segurança em Português com paginação."""
    _cursor = params.get("cursor")
    tools = [
        {
                "name": "analisar_ameaca_seguranca",
                "description": "Analisa uma ameaca de seguranca especifica no ambiente",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "threat_id": {
                                        "description": "ID ou nome da ameaca",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "threat_id"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "analisar_padroes_alertas",
                "description": "Analisa padroes comportamentais e ocorrencias repetitivas de alertas no Wazuh",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "Filtrar por ID do agente",
                                        "type": "string"
                                },
                                "time_range": {
                                        "default": "24h",
                                        "description": "Intervalo de tempo",
                                        "enum": [
                                                "1h",
                                                "6h",
                                                "12h",
                                                "1d",
                                                "24h",
                                                "7d",
                                                "30d"
                                        ],
                                        "type": "string"
                                }
                        },
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "bloquear_firewall_wazuh",
                "description": "[ACAO DE ESCRITA] Aplica uma regra de drop no firewall local do host",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "src_ip": {
                                        "description": "IP de origem",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "agent_id",
                                "src_ip"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "bloquear_ip_wazuh",
                "description": "[ACAO DE ESCRITA] Bloqueia um IP de origem malicioso no firewall do agente",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "src_ip": {
                                        "description": "IP de origem a ser bloqueado",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "agent_id",
                                "src_ip"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "buscar_alertas_por_mitre",
                "description": "Busca alertas de seguranca filtrados por tatica ou ID do MITRE ATT&CK (ex: T1059, T1105)",
                "inputSchema": {
                        "type": "object",
                        "properties": {
                                "mitre_id": {
                                        "type": "string",
                                        "default": "T1059",
                                        "description": "ID da tecnica ou tatica MITRE"
                                },
                                "time_range": {
                                        "type": "string",
                                        "default": "24h",
                                        "description": "Janela de tempo"
                                },
                                "limit": {
                                        "type": "integer",
                                        "default": 50,
                                        "description": "Limite de alertas"
                                }
                        },
                        "required": []
                }
        },
        {
                "name": "buscar_eventos_fim",
                "description": "Busca alteracoes de arquivos/registros no FIM (Syscheck)",
                "inputSchema": {
                        "type": "object",
                        "properties": {
                                "agent_id": {
                                        "type": "string",
                                        "default": "001",
                                        "description": "ID do agente"
                                },
                                "file_path": {
                                        "type": "string",
                                        "description": "Caminho do arquivo ou registro a buscar"
                                },
                                "limit": {
                                        "type": "integer",
                                        "default": 100,
                                        "description": "Limite de resultados"
                                }
                        },
                        "required": []
                }
        },
        {
                "name": "buscar_eventos_seguranca",
                "description": "Busca avancada de eventos de seguranca usando sintaxe Lucene ou filtros estruturados",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "compact": {
                                        "default": True,
                                        "description": "Retornar formato compacto",
                                        "type": "boolean"
                                },
                                "dstip": {
                                        "description": "IP de destino",
                                        "type": "string"
                                },
                                "level": {
                                        "description": "Nivel minimo de severidade",
                                        "type": "string"
                                },
                                "limit": {
                                        "default": 100,
                                        "description": "Limite de registros",
                                        "maximum": 1000,
                                        "type": "integer"
                                },
                                "query": {
                                        "description": "Consulta em formato texto/Lucene",
                                        "type": "string"
                                },
                                "rule_id": {
                                        "description": "ID da regra",
                                        "type": "string"
                                },
                                "srcip": {
                                        "description": "IP de origem",
                                        "type": "string"
                                },
                                "time_range": {
                                        "default": "24h",
                                        "description": "Intervalo de tempo",
                                        "enum": [
                                                "1h",
                                                "6h",
                                                "12h",
                                                "1d",
                                                "24h",
                                                "7d",
                                                "30d"
                                        ],
                                        "type": "string"
                                }
                        },
                        "required": [
                                "query"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "buscar_logs_gerenciador_wazuh",
                "description": "Busca em logs internos de diagnostico do servidor Wazuh Manager",
                "inputSchema": {
                        "properties": {
                                "limit": {
                                        "default": 100,
                                        "description": "Limite de linhas",
                                        "maximum": 1000,
                                        "type": "integer"
                                },
                                "query": {
                                        "description": "Termo de busca nos logs",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "query"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "buscar_vulnerabilidades_cve",
                "description": "Busca instancias de um CVE especifico (ex: CVE-2024-30078) no parque de agentes",
                "inputSchema": {
                        "type": "object",
                        "properties": {
                                "cve_id": {
                                        "type": "string",
                                        "description": "ID do CVE (ex: CVE-2024-30078)"
                                },
                                "limit": {
                                        "type": "integer",
                                        "default": 100,
                                        "description": "Limite de resultados"
                                }
                        },
                        "required": [
                                "cve_id"
                        ]
                }
        },
        {
                "name": "buscar_vulnerabilidades_pacote",
                "description": "Busca vulnerabilidades associadas a um pacote/software (ex: openssl, python)",
                "inputSchema": {
                        "type": "object",
                        "properties": {
                                "package_name": {
                                        "type": "string",
                                        "description": "Nome do pacote"
                                },
                                "limit": {
                                        "type": "integer",
                                        "default": 100,
                                        "description": "Limite de resultados"
                                }
                        },
                        "required": [
                                "package_name"
                        ]
                }
        },
        {
                "name": "buscar_vulnerabilidades_severidade",
                "description": "Filtra vulnerabilidades por nivel de severidade (critical, high, medium, low)",
                "inputSchema": {
                        "type": "object",
                        "properties": {
                                "severity": {
                                        "type": "string",
                                        "default": "critical",
                                        "description": "Nivel de severidade: critical, high, medium, low"
                                },
                                "limit": {
                                        "type": "integer",
                                        "default": 100,
                                        "description": "Limite de resultados"
                                }
                        },
                        "required": []
                }
        },
        {
                "name": "criar_decodificador_customizado_wazuh",
                "description": "[ACAO DE ESCRITA] Cria um novo arquivo XML de decodificador customizado no Wazuh Manager (/etc/decoders/{filename})",
                "inputSchema": {
                        "properties": {
                                "content": {
                                        "description": "Conteudo em formato XML do decodificador customizado",
                                        "type": "string"
                                },
                                "filename": {
                                        "default": "local_decoder.xml",
                                        "description": "Nome do arquivo XML de decodificador",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "content"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "criar_regra_customizada_wazuh",
                "description": "[ACAO DE ESCRITA] Cria um novo arquivo de regras customizadas XML no Wazuh Manager (/etc/rules/{filename})",
                "inputSchema": {
                        "properties": {
                                "content": {
                                        "description": "Conteudo em formato XML da regra customizada",
                                        "type": "string"
                                },
                                "filename": {
                                        "default": "local_rules.xml",
                                        "description": "Nome do arquivo XML de regras",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "content"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "desabilitar_usuario_wazuh",
                "description": "[ACAO DE ESCRITA] Desabilita uma conta de usuario comprometida no agente",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "username": {
                                        "description": "Nome de usuario",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "agent_id",
                                "username"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "desisolar_host_wazuh",
                "description": "[ACAO DE ESCRITA] Remove o isolamento de rede do agente",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "agent_id"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "encerrar_processo_wazuh",
                "description": "[ACAO DE ESCRITA] Encerra um processo suspeito informando o PID",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "pid": {
                                        "description": "PID do processo",
                                        "type": "integer"
                                }
                        },
                        "required": [
                                "agent_id",
                                "pid"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "estatisticas_mitre",
                "description": "Gera resumo estatistico das top taticas e tecnicas MITRE ATT&CK disparadas no ambiente",
                "inputSchema": {
                        "type": "object",
                        "properties": {
                                "time_range": {
                                        "type": "string",
                                        "default": "24h",
                                        "description": "Janela de tempo"
                                }
                        },
                        "required": []
                }
        },
        {
                "name": "excluir_decodificador_customizado_wazuh",
                "description": "[ACAO DE ESCRITA] Exclui um arquivo XML de decodificador customizado do Wazuh Manager",
                "inputSchema": {
                        "properties": {
                                "filename": {
                                        "description": "Nome do arquivo XML de decodificador a excluir",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "filename"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "excluir_regra_customizada_wazuh",
                "description": "[ACAO DE ESCRITA] Exclui um arquivo XML de regras customizadas do Wazuh Manager",
                "inputSchema": {
                        "properties": {
                                "filename": {
                                        "description": "Nome do arquivo XML de regras a excluir",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "filename"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "executar_avaliacao_risco",
                "description": "Calcula a pontuacao de risco global e identifica fatores de risco do ambiente",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                }
                        },
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "executar_teste_conformidade",
                "description": "Executa verificacoes de conformidade em padroes de seguranca (PCI-DSS, CIS, GDPR, HIPAA, NIST, SOX)",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "framework": {
                                        "description": "Padrao de conformidade",
                                        "enum": [
                                                "PCI-DSS",
                                                "CIS",
                                                "GDPR",
                                                "HIPAA",
                                                "NIST",
                                                "SOX"
                                        ],
                                        "type": "string"
                                }
                        },
                        "required": [
                                "framework"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "gerar_relatorio_cis",
                "description": "Gera relatorio de aderencia e pontuacao de conformidade CIS Benchmark do agente",
                "inputSchema": {
                        "type": "object",
                        "properties": {
                                "agent_id": {
                                        "type": "string",
                                        "default": "001",
                                        "description": "ID do agente"
                                }
                        },
                        "required": []
                }
        },
        {
                "name": "gerar_relatorio_lgpd",
                "description": "Gera relatorio de governanca de dados, privacidade e conformidade LGPD (Art. 46)",
                "inputSchema": {
                        "type": "object",
                        "properties": {
                                "time_range": {
                                        "type": "string",
                                        "default": "24h",
                                        "description": "Janela de tempo"
                                }
                        },
                        "required": []
                }
        },
        {
                "name": "gerar_relatorio_nist",
                "description": "Gera relatorio automatizado de auditoria e conformidade NIST SP 800-53",
                "inputSchema": {
                        "type": "object",
                        "properties": {
                                "time_range": {
                                        "type": "string",
                                        "default": "24h",
                                        "description": "Janela de tempo"
                                }
                        },
                        "required": []
                }
        },
        {
                "name": "gerar_relatorio_seguranca",
                "description": "Gera um relatorio de seguranca consolidado (diario, semanal ou mensal)",
                "inputSchema": {
                        "properties": {
                                "include_recommendations": {
                                        "default": True,
                                        "description": "Incluir recomendacoes",
                                        "type": "boolean"
                                },
                                "report_type": {
                                        "default": "daily",
                                        "description": "Tipo de relatorio",
                                        "enum": [
                                                "daily",
                                                "weekly",
                                                "monthly",
                                                "incident"
                                        ],
                                        "type": "string"
                                }
                        },
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "gerenciar_grupos_agente",
                "description": "[ACAO DE ESCRITA] Gerencia a associacao de agentes ou cria/exclui grupos globais no Wazuh (add, remove, set, create, delete)",
                "inputSchema": {
                        "properties": {
                                "action": {
                                        "description": "Acao a realizar (add, remove, set, create, delete)",
                                        "enum": [
                                                "add",
                                                "remove",
                                                "set",
                                                "create",
                                                "delete"
                                        ],
                                        "type": "string"
                                },
                                "agent_id": {
                                        "description": "ID do agente (obrigatorio para add, remove, set)",
                                        "type": "string"
                                },
                                "group_id": {
                                        "description": "Nome/ID do grupo",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "action",
                                "group_id"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "habilitar_usuario_wazuh",
                "description": "[ACAO DE ESCRITA] Reabilita uma conta de usuario desabilitada",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "username": {
                                        "description": "Nome de usuario",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "agent_id",
                                "username"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "investigar_incidente_wazuh",
                "description": "Orquestra automaticamente uma investigacao completa de incidente SOC/DFIR em 11 etapas (alertas, agente, processos, portas, vulnerabilidades, FIM, IOC, MITRE, timeline, risco e contencao)",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "default": "001",
                                        "description": "ID do agente a investigar (ex: 001)",
                                        "type": "string"
                                },
                                "alert_id": {
                                        "description": "ID especifico do alerta (opcional)",
                                        "type": "string"
                                },
                                "ioc": {
                                        "description": "IP, dominio ou hash para analise de reputacao (opcional)",
                                        "type": "string"
                                },
                                "rule_id": {
                                        "description": "ID especifico da regra (opcional)",
                                        "type": "string"
                                },
                                "time_range": {
                                        "default": "24h",
                                        "description": "Janela de tempo para analise (ex: 24h, 7d)",
                                        "type": "string"
                                }
                        },
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "isolar_host_wazuh",
                "description": "[ACAO DE ESCRITA] Isola um host comprometido da rede",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente a isolar",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "agent_id"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "modificar_decodificador_customizado_wazuh",
                "description": "[ACAO DE ESCRITA] Modifica ou substitui o conteudo XML de um arquivo de decodificador customizado existente",
                "inputSchema": {
                        "properties": {
                                "content": {
                                        "description": "Novo conteudo em formato XML",
                                        "type": "string"
                                },
                                "filename": {
                                        "default": "local_decoder.xml",
                                        "description": "Nome do arquivo XML de decodificador",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "content"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "modificar_regra_customizada_wazuh",
                "description": "[ACAO DE ESCRITA] Modifica ou substitui o conteudo XML de um arquivo de regras customizadas existente",
                "inputSchema": {
                        "properties": {
                                "content": {
                                        "description": "Novo conteudo em formato XML",
                                        "type": "string"
                                },
                                "filename": {
                                        "default": "local_rules.xml",
                                        "description": "Nome do arquivo XML de regras",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "content"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "negar_host_wazuh",
                "description": "[ACAO DE ESCRITA] Adiciona um IP a lista de negacao do host",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "src_ip": {
                                        "description": "IP de origem",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "agent_id",
                                "src_ip"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "obter_agentes_ativos_wazuh",
                "description": "Retorna exclusivamente a lista de agentes que estao ativos e conectados",
                "inputSchema": {
                        "properties": {},
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "obter_agentes_wazuh",
                "description": "Lista os agentes cadastrados no cluster do Wazuh com seus metadados",
                "inputSchema": {
                        "properties": {
                                "limit": {
                                        "default": 100,
                                        "description": "Limite de agentes",
                                        "maximum": 500,
                                        "type": "integer"
                                },
                                "q": {
                                        "description": "Filtro de busca por nome ou IP",
                                        "type": "string"
                                },
                                "status": {
                                        "description": "Filtrar por status",
                                        "type": "string"
                                }
                        },
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "obter_alertas_wazuh",
                "description": "Busca alertas de seguranca do Wazuh com filtros opcionais de nivel, regra, agente e data",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "Filtrar por ID de agente especifico (ex: 001)",
                                        "type": "string"
                                },
                                "compact": {
                                        "default": True,
                                        "description": "Retornar formato compacto",
                                        "type": "boolean"
                                },
                                "level": {
                                        "description": "Filtrar por nivel de severidade (ex: 12, 10+)",
                                        "type": "string"
                                },
                                "limit": {
                                        "default": 100,
                                        "description": "Limite maximo de alertas a retornar",
                                        "maximum": 1000,
                                        "type": "integer"
                                },
                                "rule_id": {
                                        "description": "Filtrar por ID de regra especifica (ex: 92213)",
                                        "type": "string"
                                },
                                "timestamp_end": {
                                        "description": "Data/hora final em formato ISO",
                                        "type": "string"
                                },
                                "timestamp_start": {
                                        "description": "Data/hora inicial em formato ISO",
                                        "type": "string"
                                }
                        },
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "obter_alteracoes_fim_agente",
                "description": "Consulta alteracoes de integridade de arquivos (FIM / Syscheck) em um agente",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "event_type": {
                                        "description": "Tipo de evento (added, modified, deleted)",
                                        "type": "string"
                                },
                                "file_path": {
                                        "description": "Caminho especifico do arquivo",
                                        "type": "string"
                                },
                                "limit": {
                                        "default": 100,
                                        "description": "Limite de alteracoes",
                                        "maximum": 500,
                                        "type": "integer"
                                }
                        },
                        "required": [
                                "agent_id"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "obter_arquivo_monitorado",
                "description": "Consulta os detalhes e modificacoes de um arquivo/registro especifico monitorado pelo FIM",
                "inputSchema": {
                        "type": "object",
                        "properties": {
                                "agent_id": {
                                        "type": "string",
                                        "default": "001",
                                        "description": "ID do agente"
                                },
                                "file_path": {
                                        "type": "string",
                                        "description": "Caminho exato do arquivo"
                                }
                        },
                        "required": [
                                "file_path"
                        ]
                }
        },
        {
                "name": "obter_configuracao_agente",
                "description": "Obtem as configuracoes e grupos de um agente monitorado",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "component": {
                                        "description": "Componente especifico da configuracao",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "agent_id"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "obter_dashboard_alertas",
                "description": "Retorna dados consolidados para dashboard executivo de alertas de seguranca",
                "inputSchema": {
                        "type": "object",
                        "properties": {
                                "time_range": {
                                        "type": "string",
                                        "default": "24h",
                                        "description": "Janela de tempo"
                                }
                        },
                        "required": []
                }
        },
        {
                "name": "obter_dashboard_vulnerabilidades",
                "description": "Retorna dados consolidados para dashboard executivo de vulnerabilidades/CVEs",
                "inputSchema": {
                        "type": "object",
                        "properties": {},
                        "required": []
                }
        },
        {
                "name": "obter_detalhes_regra_wazuh",
                "description": "Inspeciona a definicao XML, arquivo de origem e expressoes de uma regra pelo ID",
                "inputSchema": {
                        "properties": {
                                "rule_id": {
                                        "description": "ID da regra a inspecionar",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "rule_id"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "obter_estatisticas_coletor_logs_wazuh",
                "description": "Obtem estatisticas do servico coletor e decodificador de logs (wazuh-analysisd)",
                "inputSchema": {
                        "properties": {},
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "obter_estatisticas_fim",
                "description": "Retorna estatisticas globais do modulo de Integridade de Arquivos (Syscheck/FIM)",
                "inputSchema": {
                        "type": "object",
                        "properties": {
                                "agent_id": {
                                        "type": "string",
                                        "default": "001",
                                        "description": "ID do agente"
                                }
                        },
                        "required": []
                }
        },
        {
                "name": "obter_estatisticas_remoted_wazuh",
                "description": "Obtem estatisticas do servico de recepcao remota de eventos (wazuh-remoted)",
                "inputSchema": {
                        "properties": {},
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "obter_estatisticas_semanais_wazuh",
                "description": "Obtem estatisticas semanais acumuladas do servidor Wazuh",
                "inputSchema": {
                        "properties": {},
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "obter_estatisticas_wazuh",
                "description": "Obtem estatisticas gerais de desempenho do servidor Wazuh Manager",
                "inputSchema": {
                        "properties": {},
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "obter_falhas_conformidade",
                "description": "Retorna apenas os testes de conformidade com falha no agente (/sca/{agent_id}/checks?result=failed)",
                "inputSchema": {
                        "type": "object",
                        "properties": {
                                "agent_id": {
                                        "type": "string",
                                        "default": "001",
                                        "description": "ID do agente"
                                },
                                "limit": {
                                        "type": "integer",
                                        "default": 100,
                                        "description": "Limite de itens"
                                }
                        },
                        "required": []
                }
        },
        {
                "name": "obter_logs_erro_gerenciador_wazuh",
                "description": "Retorna erros recentes registrados pelo servidor Wazuh Manager",
                "inputSchema": {
                        "properties": {
                                "limit": {
                                        "default": 100,
                                        "description": "Limite de erros",
                                        "maximum": 1000,
                                        "type": "integer"
                                }
                        },
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "obter_nos_cluster_wazuh",
                "description": "Lista os nos participantes do cluster Wazuh",
                "inputSchema": {
                        "properties": {},
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "obter_pacotes_agente",
                "description": "Lista os softwares e pacotes instalados em um agente (via Syscollector)",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "limit": {
                                        "default": 100,
                                        "description": "Limite de pacotes",
                                        "maximum": 500,
                                        "type": "integer"
                                },
                                "search": {
                                        "description": "Filtro de busca por nome ou fornecedor",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "agent_id"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "obter_politicas_conformidade",
                "description": "Lista as politicas SCA ativas no agente (/sca/{agent_id})",
                "inputSchema": {
                        "type": "object",
                        "properties": {
                                "agent_id": {
                                        "type": "string",
                                        "default": "001",
                                        "description": "ID do agente"
                                }
                        },
                        "required": []
                }
        },
        {
                "name": "obter_portas_agente",
                "description": "Lista as portas de rede abertas e conexoes ativas em um agente",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "limit": {
                                        "default": 100,
                                        "description": "Limite de portas",
                                        "maximum": 500,
                                        "type": "integer"
                                }
                        },
                        "required": [
                                "agent_id"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "obter_principais_ameacas_seguranca",
                "description": "Retorna as principais ameacas de seguranca ativas no momento",
                "inputSchema": {
                        "properties": {
                                "limit": {
                                        "default": 10,
                                        "description": "Limite de ameacas",
                                        "maximum": 50,
                                        "type": "integer"
                                },
                                "time_range": {
                                        "default": "24h",
                                        "description": "Intervalo de tempo",
                                        "enum": [
                                                "1h",
                                                "6h",
                                                "12h",
                                                "1d",
                                                "24h",
                                                "7d",
                                                "30d"
                                        ],
                                        "type": "string"
                                }
                        },
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "obter_processos_agente",
                "description": "Lista os processos em execucao em um agente monitorado",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "limit": {
                                        "default": 100,
                                        "description": "Limite de processos",
                                        "maximum": 500,
                                        "type": "integer"
                                }
                        },
                        "required": [
                                "agent_id"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "obter_resultados_conformidade",
                "description": "Busca os resultados de avaliacoes de seguranca SCA/CIS do agente (/sca/{agent_id}/checks)",
                "inputSchema": {
                        "type": "object",
                        "properties": {
                                "agent_id": {
                                        "type": "string",
                                        "default": "001",
                                        "description": "ID do agente (ex: 001)"
                                },
                                "policy_id": {
                                        "type": "string",
                                        "description": "ID da politica de conformidade (opcional)"
                                },
                                "result_filter": {
                                        "type": "string",
                                        "description": "Filtro por resultado: passed ou failed (opcional)"
                                },
                                "limit": {
                                        "type": "integer",
                                        "default": 100,
                                        "description": "Limite de itens"
                                }
                        },
                        "required": []
                }
        },
        {
                "name": "obter_resumo_alertas_wazuh",
                "description": "Retorna um resumo estatistico dos alertas do Wazuh agrupados por nivel ou campo",
                "inputSchema": {
                        "properties": {
                                "group_by": {
                                        "default": "rule.level",
                                        "description": "Campo para agrupamento dos alertas",
                                        "type": "string"
                                },
                                "time_range": {
                                        "default": "24h",
                                        "description": "Intervalo de tempo",
                                        "enum": [
                                                "1h",
                                                "6h",
                                                "12h",
                                                "1d",
                                                "24h",
                                                "7d",
                                                "30d"
                                        ],
                                        "type": "string"
                                }
                        },
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "obter_resumo_decodificadores_wazuh",
                "description": "Lista os arquivos de decodificadores XML ativos no Wazuh Manager (/decoders/files)",
                "inputSchema": {
                        "properties": {},
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "obter_resumo_regras_wazuh",
                "description": "Retorna a contagem e distribuicao das regras de alerta do Wazuh por nivel de severidade",
                "inputSchema": {
                        "properties": {},
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "obter_resumo_vulnerabilidades_wazuh",
                "description": "Gera um resumo estatistico das vulnerabilidades por pacote e severidade",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                }
                        },
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "obter_saude_cluster_wazuh",
                "description": "Verifica o status de saude e desempenho do cluster Wazuh",
                "inputSchema": {
                        "properties": {},
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "obter_tecnicas_mitre",
                "description": "Lista as tecnicas e taticas MITRE ATT&CK registradas na base de regras do Wazuh",
                "inputSchema": {
                        "type": "object",
                        "properties": {
                                "limit": {
                                        "type": "integer",
                                        "default": 100,
                                        "description": "Limite de itens"
                                }
                        },
                        "required": []
                }
        },
        {
                "name": "obter_vulnerabilidades_criticas_wazuh",
                "description": "Retorna exclusivamente vulnerabilidades de severidade critica ou alta",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "limit": {
                                        "default": 100,
                                        "description": "Limite de vulnerabilidades",
                                        "maximum": 500,
                                        "type": "integer"
                                }
                        },
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "obter_vulnerabilidades_wazuh",
                "description": "Consulta vulnerabilidades (CVEs) encontradas nos agentes",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "cve": {
                                        "description": "ID de uma CVE especifica",
                                        "type": "string"
                                },
                                "limit": {
                                        "default": 100,
                                        "description": "Limite de registros",
                                        "maximum": 500,
                                        "type": "integer"
                                },
                                "severity": {
                                        "description": "Severidade (Critical, High, Medium, Low)",
                                        "type": "string"
                                }
                        },
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "permitir_firewall_wazuh",
                "description": "[ACAO DE ESCRITA] Remove regra de bloqueio do firewall",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "src_ip": {
                                        "description": "IP a permitir",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "agent_id",
                                "src_ip"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "permitir_host_wazuh",
                "description": "[ACAO DE ESCRITA] Remove um IP da lista de negacao do host",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "src_ip": {
                                        "description": "IP a permitir",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "agent_id",
                                "src_ip"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "quarentena_arquivo_wazuh",
                "description": "[ACAO DE ESCRITA] Move um arquivo suspeito para a quarentena",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "file_path": {
                                        "description": "Caminho do arquivo",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "agent_id",
                                "file_path"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "reiniciar_servico_wazuh",
                "description": "[ACAO DE ESCRITA] Reinicia o servico do agente Wazuh ou do manager",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                }
                        },
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "resposta_ativa_wazuh",
                "description": "[ACAO DE ESCRITA] Dispara uma resposta ativa arbitraria em um agente",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "arguments": {
                                        "description": "Argumentos adicionais",
                                        "items": {
                                                "type": "string"
                                        },
                                        "type": "array"
                                },
                                "command": {
                                        "description": "Comando de resposta ativa",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "command",
                                "agent_id"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "restaurar_arquivo_wazuh",
                "description": "[ACAO DE ESCRITA] Restaura um arquivo da quarentena para o local original",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "file_path": {
                                        "description": "Caminho do arquivo",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "agent_id",
                                "file_path"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "testar_mensagem_log_wazuh",
                "description": "Testa uma linha de log bruta no simulador do Wazuh (wazuh-logtest)",
                "inputSchema": {
                        "properties": {
                                "location": {
                                        "default": "syslog",
                                        "description": "Origem/cabecalho do log",
                                        "type": "string"
                                },
                                "log_message": {
                                        "description": "Linha de log bruta para testar",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "log_message"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "validar_conexao_wazuh",
                "description": "Valida a conectividade da API REST com o servidor Wazuh",
                "inputSchema": {
                        "properties": {},
                        "required": [],
                        "type": "object"
                }
        },
        {
                "name": "verificar_ip_bloqueado_wazuh",
                "description": "Confirma se um IP permanece bloqueado no agente",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "src_ip": {
                                        "description": "IP a verificar",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "agent_id",
                                "src_ip"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "verificar_isolamento_agente_wazuh",
                "description": "Confirma se o isolamento de rede do agente esta ativo",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "agent_id"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "verificar_processo_wazuh",
                "description": "Verifica se um processo especifico ainda esta rodando no agente",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "pid": {
                                        "description": "PID do processo",
                                        "type": "integer"
                                }
                        },
                        "required": [
                                "agent_id",
                                "pid"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "verificar_quarentena_arquivo_wazuh",
                "description": "Confirma se o arquivo esta contido na quarentena do agente",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "file_path": {
                                        "description": "Caminho do arquivo",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "agent_id",
                                "file_path"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "verificar_reputacao_ioc",
                "description": "Consulta a reputacao de um Indicador de Comprometimento (IP, hash ou dominio)",
                "inputSchema": {
                        "properties": {
                                "ioc_type": {
                                        "description": "Tipo do IOC",
                                        "enum": [
                                                "ip",
                                                "hash",
                                                "domain"
                                        ],
                                        "type": "string"
                                },
                                "ioc_value": {
                                        "description": "Valor do IOC",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "ioc_type",
                                "ioc_value"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "verificar_saude_agente",
                "description": "Verifica o status detalhado de saude, versao e keep-alive de um agente especifico",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "agent_id"
                        ],
                        "type": "object"
                }
        },
        {
                "name": "verificar_status_usuario_wazuh",
                "description": "Verifica o estado atual da conta do usuario (ativo ou bloqueado)",
                "inputSchema": {
                        "properties": {
                                "agent_id": {
                                        "description": "ID do agente",
                                        "type": "string"
                                },
                                "username": {
                                        "description": "Nome de usuario",
                                        "type": "string"
                                }
                        },
                        "required": [
                                "agent_id",
                                "username"
                        ],
                        "type": "object"
                }
        }
]

    # Filter tools by session scopes: hide write tools from read-only or unknown tokens
    auth_token = getattr(session, "_auth_token", None)
    if not auth_token or not auth_token.has_scope("wazuh:write"):
        tools = [t for t in tools if t["name"] not in WRITE_SCOPE_TOOLS]

    # Pagination support per MCP spec
    return {"tools": tools}


async def handle_tools_call(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """Handle tools/call method - All 53 Wazuh Security Tools with comprehensive validation."""
    tool_name = params.get("name")
    arguments = params.get("arguments", {})

    if not tool_name:
        raise ValueError("Tool name is required")

    # Validate tool name
    validate_input(tool_name, max_length=100)

    # Scope enforcement: check if the token has the required scope for this tool.
    # If auth_token is missing (should not happen in normal flow), deny write tools by default.
    auth_token = getattr(session, "_auth_token", None)
    required_scope = _get_tool_scope(tool_name)
    if required_scope == "wazuh:write" and not auth_token:
        raise ValueError(
            f"Insufficient permissions: tool '{tool_name}' requires '{required_scope}' scope. "
            f"Authentication token not found on session."
        )
    if auth_token and not auth_token.has_scope(required_scope):
        raise ValueError(
            f"Insufficient permissions: tool '{tool_name}' requires '{required_scope}' scope. "
            f"Your token has scopes: {auth_token.scopes}. "
            f"Request a token with '{required_scope}' scope to use this tool."
        )

    # Audit logging for destructive operations
    if tool_name in WRITE_SCOPE_TOOLS:
        client_id = auth_token.api_key_id if auth_token else "unknown"
        audit_logger.warning(
            f"AUDIT: tool={tool_name} client={client_id} session={session.session_id} "
            f"args={json.dumps({k: v for k, v in arguments.items() if k != 'parameters'}, default=str)}"
        )

    # Track tool execution for metrics
    import time as _time

    from wazuh_mcp_server.monitoring import record_tool_execution

    def _tool_result(text: str) -> dict:
        """Return MCP-compliant tool success response with isError field."""
        return {"content": [{"type": "text", "text": text}], "isError": False}

    def _tool_error(text: str) -> dict:
        """Return MCP-compliant tool error response with isError field."""
        return {"content": [{"type": "text", "text": text}], "isError": True}

    _start_time = _time.time()
    _success = False

    try:
        # Alert Management Tools
        if tool_name == "obter_alertas_wazuh":
            # Validate all parameters
            limit = validate_limit(arguments.get("limit"), max_val=1000)
            rule_id = validate_rule_id(arguments.get("rule_id"))
            level = arguments.get("level")
            # Validate level format: must be a number optionally followed by "+"
            if level is not None:
                import re

                level = str(level).strip()
                if not re.match(r"^[0-9]{1,2}\+?$", level):
                    raise ToolValidationError(
                        "level",
                        f"invalid format '{level}'",
                        "Use a number 0-15, optionally with '+' (e.g., '12', '10+')",
                    )
            agent_id = validate_agent_id(arguments.get("agent_id"))
            timestamp_start = validate_timestamp(arguments.get("timestamp_start"), param_name="timestamp_start")
            timestamp_end = validate_timestamp(arguments.get("timestamp_end"), param_name="timestamp_end")
            compact = validate_boolean(arguments.get("compact"), default=True, param_name="compact")

            result = await wazuh_client.get_alerts(
                limit=limit,
                rule_id=rule_id,
                level=level,
                agent_id=agent_id,
                timestamp_start=timestamp_start,
                timestamp_end=timestamp_end,
            )
            if compact:
                result = _compact_alerts_result(result)
            result = _add_truncation_warning(result, limit)
            _success = True
            return _tool_result(f"Wazuh Alerts:\n{json.dumps(result, indent=2 if not compact else None, default=str)}")

        elif tool_name == "obter_resumo_alertas_wazuh":
            time_range = validate_time_range(arguments.get("time_range"))
            group_by = arguments.get("group_by", "rule.level")
            # Validate group_by to prevent injection (only allow safe dotted field paths)
            VALID_GROUP_BY = {"rule.level", "rule.id", "rule.groups", "agent.id", "agent.name"}
            if group_by not in VALID_GROUP_BY:
                raise ToolValidationError(
                    "group_by",
                    f"invalid value '{group_by}'",
                    f"Must be one of: {', '.join(sorted(VALID_GROUP_BY))}",
                )
            result = await wazuh_client.get_alert_summary(time_range, group_by)
            _success = True
            return _tool_result(f"Alert Summary:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "analisar_padroes_alertas":
            time_range = validate_time_range(arguments.get("time_range"))
            min_frequency = validate_limit(
                arguments.get("min_frequency"), min_val=1, max_val=1000, default=5, param_name="min_frequency"
            )
            result = await wazuh_client.analyze_alert_patterns(time_range, min_frequency)
            _success = True
            return _tool_result(f"Alert Patterns:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "buscar_eventos_seguranca":
            query = validate_query(arguments.get("query"), required=True)
            time_range = validate_time_range(arguments.get("time_range"))
            limit = validate_limit(arguments.get("limit"), max_val=1000)
            compact = validate_boolean(arguments.get("compact"), default=True, param_name="compact")
            rule_id = validate_rule_id(arguments.get("rule_id"))
            agent_id = validate_agent_id(arguments.get("agent_id"))
            srcip = validate_ip_address(arguments.get("srcip"), param_name="srcip")
            dstip = validate_ip_address(arguments.get("dstip"), param_name="dstip")
            # Level is a string like "10" or "12+" — validate as simple numeric
            level_raw = arguments.get("level")
            level = None
            if level_raw is not None:
                level_str = str(level_raw).strip().rstrip("+")
                try:
                    int(level_str)
                    level = str(level_raw).strip()
                except (ValueError, TypeError):
                    raise ToolValidationError(
                        "level", f"must be a numeric value, got '{level_raw}'", "Use a number like '10' or '12+'"
                    )

            result = await wazuh_client.search_security_events(
                query, time_range, limit,
                rule_id=rule_id, agent_id=agent_id, level=level,
                srcip=srcip, dstip=dstip,
            )
            if compact:
                result = _compact_alerts_result(result)
            result = _add_truncation_warning(result, limit)
            _success = True
            return _tool_result(f"Security Events:\n{json.dumps(result, indent=2 if not compact else None, default=str)}")

        # Agent Management Tools
        elif tool_name == "obter_agentes_wazuh":
            agent_id = validate_agent_id(arguments.get("agent_id"))
            status = validate_agent_status(arguments.get("status"))
            limit = validate_limit(arguments.get("limit"), max_val=1000)

            result = await wazuh_client.get_agents(agent_id=agent_id, status=status, limit=limit)
            _success = True
            return _tool_result(f"Wazuh Agents:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_agentes_ativos_wazuh":
            result = await wazuh_client.get_running_agents()
            _success = True
            return _tool_result(f"Running Agents:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "verificar_saude_agente":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            result = await wazuh_client.check_agent_health(agent_id)
            _success = True
            return _tool_result(f"Agent Health:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_processos_agente":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            limit = validate_limit(arguments.get("limit"), max_val=1000)
            result = await wazuh_client.get_agent_processes(agent_id, limit)
            _success = True
            return _tool_result(f"Agent Processes:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_portas_agente":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            limit = validate_limit(arguments.get("limit"), max_val=1000)
            result = await wazuh_client.get_agent_ports(agent_id, limit)
            _success = True
            return _tool_result(f"Agent Ports:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_configuracao_agente":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            result = await wazuh_client.get_agent_configuration(agent_id)
            _success = True
            return _tool_result(f"Agent Configuration:\n{json.dumps(result, indent=2, default=str)}")

        # Vulnerability Management Tools
        elif tool_name == "obter_vulnerabilidades_wazuh":
            agent_id = validate_agent_id(arguments.get("agent_id"))
            severity = validate_severity(arguments.get("severity"))
            limit = validate_limit(arguments.get("limit"), max_val=500)
            compact = validate_boolean(arguments.get("compact"), default=True, param_name="compact")

            result = await wazuh_client.get_vulnerabilities(agent_id=agent_id, severity=severity, limit=limit)
            if compact:
                result = _compact_vulns_result(result)
            result = _add_truncation_warning(result, limit)
            _success = True
            return _tool_result(f"Vulnerabilities:\n{json.dumps(result, indent=2 if not compact else None, default=str)}")

        elif tool_name == "obter_vulnerabilidades_criticas_wazuh":
            limit = validate_limit(arguments.get("limit"), max_val=500, default=50, param_name="limit")
            compact = validate_boolean(arguments.get("compact"), default=True, param_name="compact")

            result = await wazuh_client.get_critical_vulnerabilities(limit)
            if compact:
                result = _compact_vulns_result(result)
            result = _add_truncation_warning(result, limit)
            _success = True
            return _tool_result(f"Critical Vulnerabilities:\n{json.dumps(result, indent=2 if not compact else None, default=str)}")

        elif tool_name == "obter_resumo_vulnerabilidades_wazuh":
            time_range = validate_time_range(arguments.get("time_range"))
            result = await wazuh_client.get_vulnerability_summary(time_range)
            _success = True
            return _tool_result(f"Vulnerability Summary:\n{json.dumps(result, indent=2, default=str)}")

        # Security Analysis Tools
        elif tool_name == "analisar_ameaca_seguranca":
            indicator_type = validate_indicator_type(arguments.get("indicator_type"))
            indicator = validate_indicator(arguments.get("indicator"), indicator_type)

            result = await wazuh_client.analyze_security_threat(indicator, indicator_type)
            _success = True
            return _tool_result(f"Threat Analysis:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "verificar_reputacao_ioc":
            indicator_type = validate_indicator_type(arguments.get("indicator_type"))
            indicator = validate_indicator(arguments.get("indicator"), indicator_type)

            result = await wazuh_client.check_ioc_reputation(indicator, indicator_type)
            _success = True
            return _tool_result(f"IoC Reputation:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "executar_avaliacao_risco":
            agent_id = validate_agent_id(arguments.get("agent_id"))
            result = await wazuh_client.perform_risk_assessment(agent_id)
            _success = True
            return _tool_result(f"Risk Assessment:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_principais_ameacas_seguranca":
            limit = validate_limit(arguments.get("limit"), min_val=1, max_val=50, default=10)
            time_range = validate_time_range(arguments.get("time_range"))

            result = await wazuh_client.get_top_security_threats(limit, time_range)
            _success = True
            return _tool_result(f"Top Security Threats:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "gerar_relatorio_seguranca":
            report_type = validate_report_type(arguments.get("report_type"))
            include_recommendations = validate_boolean(
                arguments.get("include_recommendations"), default=True, param_name="include_recommendations"
            )

            result = await wazuh_client.generate_security_report(report_type, include_recommendations)
            _success = True
            return _tool_result(f"Security Report:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "executar_teste_conformidade":
            framework = validate_compliance_framework(arguments.get("framework"))
            agent_id = validate_agent_id(arguments.get("agent_id"))

            result = await wazuh_client.run_compliance_check(framework, agent_id)
            _success = True
            return _tool_result(f"Compliance Check:\n{json.dumps(result, indent=2, default=str)}")

        # System Monitoring Tools
        elif tool_name == "obter_estatisticas_wazuh":
            result = await wazuh_client.get_wazuh_statistics()
            _success = True
            return _tool_result(f"Wazuh Statistics:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_estatisticas_semanais_wazuh":
            result = await wazuh_client.get_weekly_stats()
            _success = True
            return _tool_result(f"Weekly Statistics:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_saude_cluster_wazuh":
            result = await wazuh_client.get_cluster_health()
            _success = True
            return _tool_result(f"Cluster Health:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_nos_cluster_wazuh":
            result = await wazuh_client.get_cluster_nodes()
            _success = True
            return _tool_result(f"Cluster Nodes:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_resumo_regras_wazuh":
            result = await wazuh_client.get_rules_summary()
            _success = True
            return _tool_result(f"Rules Summary:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_estatisticas_remoted_wazuh":
            result = await wazuh_client.get_remoted_stats()
            _success = True
            return _tool_result(f"Remoted Statistics:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_estatisticas_coletor_logs_wazuh":
            result = await wazuh_client.get_log_collector_stats()
            _success = True
            return _tool_result(f"Log Collector Statistics:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "buscar_logs_gerenciador_wazuh":
            query = validate_query(arguments.get("query"), required=True)
            limit = validate_limit(arguments.get("limit"), max_val=1000)

            result = await wazuh_client.search_manager_logs(query, limit)
            _success = True
            return _tool_result(f"Manager Logs:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_logs_erro_gerenciador_wazuh":
            limit = validate_limit(arguments.get("limit"), max_val=1000)
            result = await wazuh_client.get_manager_error_logs(limit)
            _success = True
            return _tool_result(f"Manager Error Logs:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "validar_conexao_wazuh":
            result = await wazuh_client.validate_connection()
            _success = True
            return _tool_result(f"Connection Validation:\n{json.dumps(result, indent=2, default=str)}")

        # Active Response / Action Tools
        elif tool_name == "bloquear_ip_wazuh":
            ip_address = validate_ip_address(arguments.get("ip_address"), required=True)
            duration = (
                validate_limit(arguments.get("duration"), min_val=0, max_val=86400, param_name="duration")
                if arguments.get("duration") is not None
                else 0
            )
            agent_id = validate_agent_id(arguments.get("agent_id"))
            result = await wazuh_client.block_ip(ip_address, duration, agent_id)
            _success = True
            return _tool_result(f"Block IP Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "isolar_host_wazuh":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            result = await wazuh_client.isolate_host(agent_id)
            _success = True
            return _tool_result(f"Isolate Host Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "encerrar_processo_wazuh":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            process_id = arguments.get("process_id")
            if process_id is None:
                raise ValueError("Parameter 'process_id' is required")
            process_id = validate_limit(process_id, min_val=1, max_val=999999, param_name="process_id")
            result = await wazuh_client.kill_process(agent_id, process_id)
            _success = True
            return _tool_result(f"Kill Process Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "desabilitar_usuario_wazuh":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            username = validate_username(arguments.get("username"), required=True)
            result = await wazuh_client.disable_user(agent_id, username)
            _success = True
            return _tool_result(f"Disable User Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "quarentena_arquivo_wazuh":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            file_path = validate_file_path(arguments.get("file_path"), required=True)
            result = await wazuh_client.quarantine_file(agent_id, file_path)
            _success = True
            return _tool_result(f"Quarantine File Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "resposta_ativa_wazuh":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            command = validate_active_response_command(arguments.get("command"), required=True)
            parameters = arguments.get("parameters")
            result = await wazuh_client.run_active_response(agent_id, command, parameters)
            _success = True
            return _tool_result(f"Active Response Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "bloquear_firewall_wazuh":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            src_ip = validate_ip_address(arguments.get("src_ip"), required=True, param_name="src_ip")
            duration = (
                validate_limit(arguments.get("duration"), min_val=0, max_val=86400, param_name="duration")
                if arguments.get("duration") is not None
                else 0
            )
            result = await wazuh_client.firewall_drop(agent_id, src_ip, duration)
            _success = True
            return _tool_result(f"Firewall Drop Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "negar_host_wazuh":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            src_ip = validate_ip_address(arguments.get("src_ip"), required=True, param_name="src_ip")
            result = await wazuh_client.host_deny(agent_id, src_ip)
            _success = True
            return _tool_result(f"Host Deny Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "reiniciar_servico_wazuh":
            target = arguments.get("target", "").strip()
            if not target:
                raise ValueError("Parameter 'target' is required. Use an agent ID or 'manager'.")
            if target != "manager":
                validate_agent_id(target, required=True, param_name="target")
            result = await wazuh_client.restart_service(target)
            _success = True
            return _tool_result(f"Restart Result:\n{json.dumps(result, indent=2, default=str)}")

        # Verification Tools
        elif tool_name == "verificar_ip_bloqueado_wazuh":
            ip_address = validate_ip_address(arguments.get("ip_address"), required=True)
            agent_id = validate_agent_id(arguments.get("agent_id"))
            result = await wazuh_client.check_blocked_ip(ip_address, agent_id)
            _success = True
            return _tool_result(f"Blocked IP Check:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "verificar_isolamento_agente_wazuh":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            result = await wazuh_client.check_agent_isolation(agent_id)
            _success = True
            return _tool_result(f"Agent Isolation Check:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "verificar_processo_wazuh":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            process_id = arguments.get("process_id")
            if process_id is None:
                raise ValueError("Parameter 'process_id' is required")
            process_id = validate_limit(process_id, min_val=1, max_val=999999, param_name="process_id")
            result = await wazuh_client.check_process(agent_id, process_id)
            _success = True
            return _tool_result(f"Process Check:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "verificar_status_usuario_wazuh":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            username = validate_username(arguments.get("username"), required=True)
            result = await wazuh_client.check_user_status(agent_id, username)
            _success = True
            return _tool_result(f"User Status Check:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "verificar_quarentena_arquivo_wazuh":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            file_path = validate_file_path(arguments.get("file_path"), required=True)
            result = await wazuh_client.check_file_quarantine(agent_id, file_path)
            _success = True
            return _tool_result(f"File Quarantine Check:\n{json.dumps(result, indent=2, default=str)}")

        # Rollback Tools
        elif tool_name == "desisolar_host_wazuh":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            result = await wazuh_client.unisolate_host(agent_id)
            _success = True
            return _tool_result(f"Unisolate Host Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "habilitar_usuario_wazuh":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            username = validate_username(arguments.get("username"), required=True)
            result = await wazuh_client.enable_user(agent_id, username)
            _success = True
            return _tool_result(f"Enable User Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "restaurar_arquivo_wazuh":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            file_path = validate_file_path(arguments.get("file_path"), required=True)
            result = await wazuh_client.restore_file(agent_id, file_path)
            _success = True
            return _tool_result(f"Restore File Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "permitir_firewall_wazuh":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            src_ip = validate_ip_address(arguments.get("src_ip"), required=True, param_name="src_ip")
            result = await wazuh_client.firewall_allow(agent_id, src_ip)
            _success = True
            return _tool_result(f"Firewall Allow Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "permitir_host_wazuh":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            src_ip = validate_ip_address(arguments.get("src_ip"), required=True, param_name="src_ip")
            result = await wazuh_client.host_allow(agent_id, src_ip)
            _success = True
            return _tool_result(f"Host Allow Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_alteracoes_fim_agente":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            limit = arguments.get("limit", 100)
            file_path = arguments.get("file_path")
            event_type = arguments.get("event_type")
            result = await wazuh_client.get_agent_fim_changes(agent_id, limit=limit, file_path=file_path, event_type=event_type)
            _success = True
            return _tool_result(f"Agent FIM Changes:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_detalhes_regra_wazuh":
            rule_id = arguments.get("rule_id")
            if not rule_id:
                raise ValueError("rule_id is required")
            result = await wazuh_client.get_rule_details(str(rule_id))
            _success = True
            return _tool_result(f"Rule Details:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "testar_mensagem_log_wazuh":
            log_message = arguments.get("log_message")
            if not log_message:
                raise ValueError("log_message is required")
            location = arguments.get("location", "syslog")
            result = await wazuh_client.test_log_message(log_message, location=location)
            _success = True
            return _tool_result(f"Logtest Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "gerenciar_grupos_agente":
            action = arguments.get("action")
            group_id = arguments.get("group_id")
            agent_id = arguments.get("agent_id")
            if not action or not group_id:
                raise ValueError("action and group_id are required")
            result = await wazuh_client.manage_agent_groups(action, group_id, agent_id=agent_id)
            _success = True
            return _tool_result(f"Gerenciamento de Grupos Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "criar_regra_customizada_wazuh":
            content_xml = arguments.get("content")
            filename = arguments.get("filename", "local_rules.xml")
            if not content_xml:
                raise ValueError("content is required")
            result = await wazuh_client.create_custom_rule(content_xml, filename=filename)
            _success = True
            return _tool_result(f"Criar Regra Customizada Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "modificar_regra_customizada_wazuh":
            content_xml = arguments.get("content")
            filename = arguments.get("filename", "local_rules.xml")
            if not content_xml:
                raise ValueError("content is required")
            result = await wazuh_client.modify_custom_rule(content_xml, filename=filename)
            _success = True
            return _tool_result(f"Modificar Regra Customizada Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "excluir_regra_customizada_wazuh":
            filename = arguments.get("filename")
            if not filename:
                raise ValueError("filename is required")
            result = await wazuh_client.delete_custom_rule(filename)
            _success = True
            return _tool_result(f"Excluir Regra Customizada Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_resumo_decodificadores_wazuh":
            result = await wazuh_client.get_decoders_summary()
            _success = True
            return _tool_result(f"Resumo Decodificadores Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "criar_decodificador_customizado_wazuh":
            content_xml = arguments.get("content")
            filename = arguments.get("filename", "local_decoder.xml")
            if not content_xml:
                raise ValueError("content is required")
            result = await wazuh_client.create_custom_decoder(content_xml, filename=filename)
            _success = True
            return _tool_result(f"Criar Decodificador Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "modificar_decodificador_customizado_wazuh":
            content_xml = arguments.get("content")
            filename = arguments.get("filename", "local_decoder.xml")
            if not content_xml:
                raise ValueError("content is required")
            result = await wazuh_client.modify_custom_decoder(content_xml, filename=filename)
            _success = True
            return _tool_result(f"Modificar Decodificador Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "excluir_decodificador_customizado_wazuh":
            filename = arguments.get("filename")
            if not filename:
                raise ValueError("filename is required")
            result = await wazuh_client.delete_custom_decoder(filename)
            _success = True
            return _tool_result(f"Excluir Decodificador Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "investigar_incidente_wazuh":
            agent_id = arguments.get("agent_id", "001")
            alert_id = arguments.get("alert_id")
            rule_id = arguments.get("rule_id")
            ioc = arguments.get("ioc")
            time_range = arguments.get("time_range", "24h")
            result = await wazuh_client.investigate_incident(
                agent_id=agent_id, alert_id=alert_id, rule_id=rule_id, ioc=ioc, time_range=time_range
            )
            _success = True
            return _tool_result(f"Investigacao de Incidente Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_resultados_conformidade":
            agent_id = arguments.get("agent_id", "001")
            policy_id = arguments.get("policy_id")
            result_filter = arguments.get("result_filter")
            limit = arguments.get("limit", 100)
            result = await wazuh_client.get_sca_checks(agent_id=agent_id, policy_id=policy_id, result_filter=result_filter, limit=limit)
            _success = True
            return _tool_result(f"Resultados Conformidade Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_politicas_conformidade":
            agent_id = arguments.get("agent_id", "001")
            result = await wazuh_client.get_sca_policies(agent_id=agent_id)
            _success = True
            return _tool_result(f"Politicas Conformidade Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_falhas_conformidade":
            agent_id = arguments.get("agent_id", "001")
            limit = arguments.get("limit", 100)
            result = await wazuh_client.get_sca_failures(agent_id=agent_id, limit=limit)
            _success = True
            return _tool_result(f"Falhas Conformidade Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_estatisticas_fim":
            agent_id = arguments.get("agent_id", "001")
            result = await wazuh_client.get_fim_stats(agent_id=agent_id)
            _success = True
            return _tool_result(f"Estatisticas FIM Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "buscar_eventos_fim":
            agent_id = arguments.get("agent_id", "001")
            file_path = arguments.get("file_path")
            limit = arguments.get("limit", 100)
            result = await wazuh_client.search_fim_events(agent_id=agent_id, file_path=file_path, limit=limit)
            _success = True
            return _tool_result(f"Eventos FIM Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_arquivo_monitorado":
            agent_id = arguments.get("agent_id", "001")
            file_path = arguments.get("file_path", "")
            result = await wazuh_client.get_monitored_file(agent_id=agent_id, file_path=file_path)
            _success = True
            return _tool_result(f"Arquivo Monitorado Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "buscar_vulnerabilidades_cve":
            cve_id = arguments.get("cve_id", "")
            limit = arguments.get("limit", 100)
            result = await wazuh_client.search_vulnerabilities_by_cve(cve_id=cve_id, limit=limit)
            _success = True
            return _tool_result(f"Vulnerabilidades por CVE Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "buscar_vulnerabilidades_pacote":
            package_name = arguments.get("package_name", "")
            limit = arguments.get("limit", 100)
            result = await wazuh_client.search_vulnerabilities_by_package(package_name=package_name, limit=limit)
            _success = True
            return _tool_result(f"Vulnerabilidades por Pacote Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "buscar_vulnerabilidades_severidade":
            severity = arguments.get("severity", "critical")
            limit = arguments.get("limit", 100)
            result = await wazuh_client.search_vulnerabilities_by_severity(severity=severity, limit=limit)
            _success = True
            return _tool_result(f"Vulnerabilidades por Severidade Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_tecnicas_mitre":
            limit = arguments.get("limit", 100)
            result = await wazuh_client.get_mitre_techniques(limit=limit)
            _success = True
            return _tool_result(f"Tecnicas MITRE Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "buscar_alertas_por_mitre":
            mitre_id = arguments.get("mitre_id", "T1059")
            time_range = arguments.get("time_range", "24h")
            limit = arguments.get("limit", 50)
            result = await wazuh_client.search_alerts_by_mitre(mitre_id=mitre_id, time_range=time_range, limit=limit)
            _success = True
            return _tool_result(f"Alertas por MITRE Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "estatisticas_mitre":
            time_range = arguments.get("time_range", "24h")
            result = await wazuh_client.get_mitre_stats(time_range=time_range)
            _success = True
            return _tool_result(f"Estatisticas MITRE Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_dashboard_alertas":
            time_range = arguments.get("time_range", "24h")
            result = await wazuh_client.get_alerts_dashboard(time_range=time_range)
            _success = True
            return _tool_result(f"Dashboard Alertas Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_dashboard_vulnerabilidades":
            result = await wazuh_client.get_vulnerability_dashboard()
            _success = True
            return _tool_result(f"Dashboard Vulnerabilidades Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "gerar_relatorio_nist":
            time_range = arguments.get("time_range", "24h")
            result = await wazuh_client.generate_nist_report(time_range=time_range)
            _success = True
            return _tool_result(f"Relatorio NIST Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "gerar_relatorio_cis":
            agent_id = arguments.get("agent_id", "001")
            result = await wazuh_client.generate_cis_report(agent_id=agent_id)
            _success = True
            return _tool_result(f"Relatorio CIS Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "gerar_relatorio_lgpd":
            time_range = arguments.get("time_range", "24h")
            result = await wazuh_client.generate_lgpd_report(time_range=time_range)
            _success = True
            return _tool_result(f"Relatorio LGPD Result:\n{json.dumps(result, indent=2, default=str)}")

        elif tool_name == "obter_pacotes_agente":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            limit = arguments.get("limit", 100)
            search = arguments.get("search")
            result = await wazuh_client.get_agent_packages(agent_id, limit=limit, search=search)
            _success = True
            return _tool_result(f"Agent Packages:\n{json.dumps(result, indent=2, default=str)}")

        else:
            raise ValueError(f"Unknown tool: {tool_name}. Use 'tools/list' to see available tools.")

    except ToolValidationError as e:
        # Parameter validation errors - return tool-level error with actionable guidance
        logger.warning(f"Tool validation error in {tool_name}: {e}")
        return _tool_error(str(e))

    except IndexerNotConfiguredError as e:
        # Provide helpful error for vulnerability tools when indexer is not configured
        logger.warning(f"Indexer not configured for tool {tool_name}: {e}")
        return _tool_error(str(e))

    except ConnectionError as e:
        # Network/connection errors - provide retry guidance
        logger.error(f"Connection error in tool {tool_name}: {e}")
        return _tool_error(f"Connection failed: {str(e)}. Check Wazuh server connectivity and try again.")

    except Exception as e:
        logger.error(f"Tool execution error in {tool_name}: {e}", exc_info=True)
        return _tool_error(f"Tool execution failed: {str(e)}")

    finally:
        # Record tool execution metrics
        _duration = _time.time() - _start_time
        record_tool_execution(tool_name, _duration, _success)


# MCP Method Registry - Full MCP 2025-03-26 Compliance
MCP_METHODS = {
    # Lifecycle methods
    "initialize": handle_initialize,
    "ping": handle_ping,
    # Tools methods
    "tools/list": handle_tools_list,
    "tools/call": handle_tools_call,
    # Prompts methods
    "prompts/list": handle_prompts_list,
    "prompts/get": handle_prompts_get,
    # Resources methods
    "resources/list": handle_resources_list,
    "resources/read": handle_resources_read,
    "resources/templates/list": handle_resources_templates_list,
    # Logging methods
    "logging/setLevel": handle_logging_set_level,
    # Completion methods
    "completion/complete": handle_completion_complete,
}


# Notification handlers (don't return responses)
async def handle_cancelled_notification(params: Dict[str, Any], session: MCPSession) -> None:
    """Handle notifications/cancelled - acknowledge cancellation request."""
    request_id = params.get("requestId")
    reason = params.get("reason", "Unknown")
    logger.debug(f"Request {request_id} cancelled: {reason}")


MCP_NOTIFICATIONS = {
    "notifications/initialized": handle_initialized_notification,
    "notifications/cancelled": handle_cancelled_notification,
}


async def process_mcp_notification(method: str, params: Dict[str, Any], session: MCPSession) -> None:
    """
    Process MCP notification (no response expected).
    Per MCP spec, notifications MUST NOT receive responses.
    """
    if method in MCP_NOTIFICATIONS:
        handler = MCP_NOTIFICATIONS[method]
        try:
            await handler(params, session)
        except Exception as e:
            # Log but don't return error - notifications don't get responses
            logger.error(f"Error processing notification {method}: {e}")
    else:
        logger.debug(f"Received unknown notification: {method}")


async def process_mcp_request(request: MCPRequest, session: MCPSession) -> MCPResponse:
    """Process individual MCP request per JSON-RPC 2.0 specification."""
    try:
        # Check if method exists
        if request.method not in MCP_METHODS:
            # Check if it's a notification method being called as request
            if request.method in MCP_NOTIFICATIONS:
                return create_error_response(
                    request.id,
                    MCP_ERRORS["INVALID_REQUEST"],
                    f"'{request.method}' is a notification, not a request method",
                )
            return create_error_response(
                request.id, MCP_ERRORS["METHOD_NOT_FOUND"], f"Method '{request.method}' not found"
            )

        # Execute method handler
        handler = MCP_METHODS[request.method]
        result = await handler(request.params or {}, session)

        return create_success_response(request.id, result)

    except ValueError as e:
        return create_error_response(request.id, MCP_ERRORS["INVALID_PARAMS"], str(e))
    except Exception as e:
        from wazuh_mcp_server.monitoring import structured_logger

        structured_logger.error(
            f"Internal error processing {request.method}",
            exc_info=True,
            method=request.method,
            request_id=str(request.id) if request.id else None,
            error_type=type(e).__name__,
            error_message=str(e),
        )
        return create_error_response(request.id, MCP_ERRORS["INTERNAL_ERROR"], "Internal server error")


async def generate_sse_events(session: MCPSession, event_id_counter: int = 0, track_connection: bool = False):
    """
    Generate Server-Sent Events for MCP Streamable HTTP transport.

    Per MCP 2025-11-25 spec:
    - SSE events MUST include an 'id' field for resumability
    - Server SHOULD immediately send a priming event with event ID and empty data
    - Server SHOULD send retry field to indicate reconnection delay

    Args:
        session: The MCP session
        event_id_counter: Starting event ID
        track_connection: If True, decrement ACTIVE_CONNECTIONS when stream ends
    """
    event_id = event_id_counter

    try:
        # Per 2025-11-25 spec: "The server SHOULD immediately send an SSE event
        # consisting of an event ID and an empty data field in order to prime
        # the client to reconnect (using that event ID as Last-Event-ID)"
        event_id += 1
        yield f"id: {event_id}\nretry: 3000\ndata: \n\n"

        # Send session info as a JSON-RPC notification
        event_id += 1
        session_notification = {"jsonrpc": "2.0", "method": "notifications/session", "params": session.to_dict()}
        yield f"id: {event_id}\nevent: message\ndata: {json.dumps(session_notification)}\n\n"

        # Send capabilities notification
        event_id += 1
        capabilities_notification = {
            "jsonrpc": "2.0",
            "method": "notifications/capabilities",
            "params": {"tools": True, "resources": True, "prompts": True, "logging": True},
        }
        yield f"id: {event_id}\nevent: message\ndata: {json.dumps(capabilities_notification)}\n\n"

        # Send periodic keepalive (ping) to maintain connection
        while True:
            event_id += 1
            ping_notification = {
                "jsonrpc": "2.0",
                "method": "notifications/ping",
                "params": {"timestamp": datetime.now(timezone.utc).isoformat()},
            }
            yield f"id: {event_id}\nevent: message\ndata: {json.dumps(ping_notification)}\n\n"
            await asyncio.sleep(30)
    except (asyncio.CancelledError, GeneratorExit):
        logger.debug(f"SSE connection closed for session {session.session_id}")
    finally:
        if track_connection:
            ACTIVE_CONNECTIONS.dec()


def is_json_rpc_notification(message: Dict[str, Any]) -> bool:
    """Check if a JSON-RPC message is a notification (no 'id' field)."""
    return "method" in message and "id" not in message


def is_json_rpc_response(message: Dict[str, Any]) -> bool:
    """Check if a JSON-RPC message is a response (has 'result' or 'error', no 'method')."""
    return ("result" in message or "error" in message) and "method" not in message


def is_json_rpc_request(message: Dict[str, Any]) -> bool:
    """Check if a JSON-RPC message is a request (has 'method' and 'id')."""
    return "method" in message and "id" in message


@app.get("/")
@app.post("/")
async def mcp_endpoint(
    request: Request,
    authorization: str = Header(None),
    origin: Optional[str] = Header(None),
    accept: Optional[str] = Header(None),
    mcp_session_id: Optional[str] = Header(None, alias="MCP-Session-Id"),
    last_event_id: Optional[str] = Header(None, alias="Last-Event-ID"),
):
    """
    Main MCP protocol endpoint supporting both GET and POST.
    GET: Returns SSE stream for real-time communication
    POST: Handles JSON-RPC requests
    """
    # Verify authentication based on configured mode
    auth_token = await verify_authentication(authorization, config)

    # Track active connections (request counting handled by monitoring middleware)
    ACTIVE_CONNECTIONS.inc()
    _sse_returned = False  # Track if SSE stream was returned (generator handles decrement)

    try:
        # Origin validation per MCP 2025-11-25 spec
        validate_origin_header(origin, config.ALLOWED_ORIGINS)

        # Rate limiting
        client_ip = request.client.host if request.client else "unknown"
        allowed, retry_after = rate_limiter.is_allowed(client_ip)
        if not allowed:
            headers = {"Retry-After": str(retry_after)} if retry_after else {}
            raise HTTPException(status_code=429, detail="Rate limit exceeded", headers=headers)

        # Session validation per MCP Streamable HTTP spec
        if mcp_session_id:
            existing_session = await sessions.get(mcp_session_id)
            if not existing_session:
                raise HTTPException(
                    status_code=404, detail="Session not found. Please start a new session with InitializeRequest."
                )
            if existing_session.is_expired():
                await sessions.remove(mcp_session_id)
                _initialized_sessions.pop(mcp_session_id, None)
                raise HTTPException(
                    status_code=404, detail="Session expired. Please start a new session with InitializeRequest."
                )
            session = existing_session
            session.update_activity()
            await sessions.set(mcp_session_id, session)
        else:
            session = await get_or_create_session(None, origin)

        session._auth_token = auth_token  # Store token for scope checks in tool handlers

        # Handle GET request (SSE)
        if request.method == "GET":
            if accept and "text/event-stream" in accept:
                # track_connection=True: decrement happens when stream closes
                _sse_returned = True
                response = StreamingResponse(
                    generate_sse_events(session, track_connection=True),
                    media_type="text/event-stream",
                    headers={
                        "Cache-Control": "no-cache",
                        "Connection": "keep-alive",
                        "MCP-Session-Id": session.session_id,
                        "Access-Control-Expose-Headers": "MCP-Session-Id",
                    },
                )
                return response
            else:
                # Return JSON response for non-SSE clients
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "id": None,
                        "result": {
                            "protocolVersion": "2025-03-26",
                            "serverInfo": {"name": "Wazuh MCP Server", "version": __version__},
                            "session": session.to_dict(),
                        },
                    },
                    headers={"MCP-Session-Id": session.session_id, "Access-Control-Expose-Headers": "MCP-Session-Id"},
                )

        # Handle POST request (JSON-RPC)
        elif request.method == "POST":
            try:
                body = await request.json()
            except json.JSONDecodeError:
                return JSONResponse(
                    content=create_error_response(None, MCP_ERRORS["PARSE_ERROR"], "Invalid JSON").dict(),
                    status_code=400,
                )

            # Handle batch requests
            if isinstance(body, list):
                if not body:
                    return JSONResponse(
                        content=create_error_response(
                            None, MCP_ERRORS["INVALID_REQUEST"], "Empty batch request"
                        ).dict(),
                        status_code=400,
                    )
                if len(body) > MAX_BATCH_SIZE:
                    return JSONResponse(
                        content=create_error_response(
                            None, MCP_ERRORS["INVALID_REQUEST"], f"Batch too large (max {MAX_BATCH_SIZE})"
                        ).dict(),
                        status_code=400,
                    )

                # Per MCP Streamable HTTP spec: If the input consists solely of
                # notifications or responses, return HTTP 202 Accepted with no body
                has_requests = any(is_json_rpc_request(item) if isinstance(item, dict) else False for item in body)

                if not has_requests:
                    # Process all notifications before returning 202
                    for item in body:
                        if isinstance(item, dict) and is_json_rpc_notification(item):
                            method = item.get("method", "")
                            params = item.get("params", {})
                            await process_mcp_notification(method, params, session)
                    logger.debug(f"Processed batch of {len(body)} notifications/responses")
                    return Response(
                        status_code=202,
                        headers={
                            "MCP-Session-Id": session.session_id,
                            "Access-Control-Expose-Headers": "MCP-Session-Id",
                        },
                    )

                # Process batch containing requests
                responses = []
                for item in body:
                    # Process notifications but don't add to responses
                    if isinstance(item, dict) and is_json_rpc_notification(item):
                        method = item.get("method", "")
                        params = item.get("params", {})
                        await process_mcp_notification(method, params, session)
                        continue
                    # Skip responses
                    if isinstance(item, dict) and is_json_rpc_response(item):
                        continue
                    try:
                        if not isinstance(item, dict):
                            raise ValidationError.from_exception_data(
                                "MCPRequest", line_errors=[], input_type="python"
                            )
                        mcp_request = MCPRequest(**item)
                        response = await process_mcp_request(mcp_request, session)
                        responses.append(response.dict())
                    except (ValidationError, TypeError) as e:
                        responses.append(
                            create_error_response(
                                item.get("id") if isinstance(item, dict) else None,
                                MCP_ERRORS["INVALID_REQUEST"],
                                f"Invalid request format: {e}",
                            ).dict()
                        )

                return JSONResponse(
                    content=responses,
                    headers={"MCP-Session-Id": session.session_id, "Access-Control-Expose-Headers": "MCP-Session-Id"},
                )

            # Handle single message
            else:
                # Per MCP spec: notifications and responses return HTTP 202 Accepted
                if isinstance(body, dict):
                    if is_json_rpc_notification(body):
                        # Process the notification (no response)
                        method = body.get("method", "")
                        params = body.get("params", {})
                        await process_mcp_notification(method, params, session)
                        logger.debug(f"Processed notification: {method}")
                        return Response(
                            status_code=202,
                            headers={
                                "MCP-Session-Id": session.session_id,
                                "Access-Control-Expose-Headers": "MCP-Session-Id",
                            },
                        )
                    elif is_json_rpc_response(body):
                        # Client sending a response - just acknowledge
                        logger.debug("Received client response")
                        return Response(
                            status_code=202,
                            headers={
                                "MCP-Session-Id": session.session_id,
                                "Access-Control-Expose-Headers": "MCP-Session-Id",
                            },
                        )

                # Handle request
                try:
                    mcp_request = MCPRequest(**body)
                    response = await process_mcp_request(mcp_request, session)
                    return JSONResponse(
                        content=response.dict(),
                        headers={
                            "MCP-Session-Id": session.session_id,
                            "Access-Control-Expose-Headers": "MCP-Session-Id",
                        },
                    )
                except ValidationError as e:
                    return JSONResponse(
                        content=create_error_response(
                            body.get("id") if isinstance(body, dict) else None,
                            MCP_ERRORS["INVALID_REQUEST"],
                            f"Invalid request format: {e}",
                        ).dict(),
                        status_code=400,
                    )

        else:
            raise HTTPException(status_code=405, detail="Method not allowed")

    finally:
        # Only decrement for non-SSE responses; SSE generator handles its own decrement
        if not _sse_returned:
            ACTIVE_CONNECTIONS.dec()


# Official MCP Remote Server SSE endpoint - as per Anthropic standards
@app.get("/sse")
async def mcp_sse_endpoint(
    request: Request,
    authorization: str = Header(None),
    origin: Optional[str] = Header(None),
    mcp_session_id: Optional[str] = Header(None, alias="MCP-Session-Id"),
    last_event_id: Optional[str] = Header(None, alias="Last-Event-ID"),
):
    """
    Official MCP SSE endpoint following Anthropic standards.
    URL format: https://<server_address>/sse
    This is the standard endpoint that Claude Desktop connects to.

    Supports authentication modes: bearer (default), oauth, none (authless)
    """
    # Verify authentication based on configured mode
    auth_token = await verify_authentication(authorization, config)

    # Origin validation per MCP 2025-11-25 spec
    validate_origin_header(origin, config.ALLOWED_ORIGINS)

    # Rate limiting
    client_ip = request.client.host if request.client else "unknown"
    allowed, retry_after = rate_limiter.is_allowed(client_ip)
    if not allowed:
        headers = {"Retry-After": str(retry_after)} if retry_after else {}
        raise HTTPException(status_code=429, detail="Rate limit exceeded", headers=headers)

    # Session validation: if client provides session ID but session doesn't exist, return 404
    # Done BEFORE incrementing ACTIVE_CONNECTIONS to avoid counter leak on early errors.
    if mcp_session_id:
        existing_session = await sessions.get(mcp_session_id)
        if not existing_session:
            raise HTTPException(status_code=404, detail="Session not found")
        session = existing_session
        session.update_activity()
        await sessions.set(mcp_session_id, session)
    else:
        session = await get_or_create_session(None, origin)
    session.authenticated = True  # Mark as authenticated via bearer token
    session._auth_token = auth_token  # Store token for scope checks in tool handlers

    # Track active connections — only after validation passes.
    # The SSE generator will decrement when the stream closes (track_connection=True).
    ACTIVE_CONNECTIONS.inc()

    try:
        response = StreamingResponse(
            generate_sse_events(session, track_connection=True),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "MCP-Session-Id": session.session_id,
                "Access-Control-Expose-Headers": "MCP-Session-Id",
            },
        )
        return response

    except Exception as e:
        ACTIVE_CONNECTIONS.dec()
        logger.error(f"SSE endpoint error: {e}")
        raise HTTPException(status_code=500, detail="SSE stream error")


# Standard MCP Endpoint - Streamable HTTP Transport (2025-11-25 Specification)
@app.post("/mcp")
@app.get("/mcp")
async def mcp_streamable_http_endpoint(
    request: Request,
    authorization: str = Header(None),
    origin: Optional[str] = Header(None),
    mcp_protocol_version: Optional[str] = Header(None, alias="MCP-Protocol-Version"),
    mcp_session_id: Optional[str] = Header(None, alias="MCP-Session-Id"),
    accept: Optional[str] = Header("application/json"),
    last_event_id: Optional[str] = Header(None, alias="Last-Event-ID"),
):
    """
    Standard MCP endpoint using Streamable HTTP transport (2025-11-25 spec).

    Supports:
    - POST: JSON-RPC requests (single message per 2025-11-25 spec)
    - GET: SSE stream initiation (requires Accept: text/event-stream)
    - DELETE: Session termination (see separate endpoint)

    This is the RECOMMENDED endpoint for MCP clients. Legacy /sse remains for backwards compatibility.
    Supports authentication modes: bearer (default), oauth, none (authless)
    """
    # Validate protocol version per 2025-11-25 spec (strict mode returns 400 for invalid)
    protocol_version = validate_protocol_version(mcp_protocol_version, strict=True)

    # Verify authentication based on configured mode
    auth_token = await verify_authentication(authorization, config)

    # Origin validation per 2025-11-25 spec
    # Only validate if Origin is present; if present and invalid, return 403
    validate_origin_header(origin, config.ALLOWED_ORIGINS)

    # Rate limiting
    client_ip = request.client.host if request.client else "unknown"
    allowed, retry_after = rate_limiter.is_allowed(client_ip)
    if not allowed:
        headers = {"Retry-After": str(retry_after)} if retry_after else {}
        raise HTTPException(status_code=429, detail="Rate limit exceeded", headers=headers)

    # Track active connections (metrics tracked after processing)
    ACTIVE_CONNECTIONS.inc()
    _sse_returned = False  # Track if SSE stream was returned (generator handles decrement)
    _status_code = 200  # Track actual status code for metrics

    try:
        # Session validation per MCP Streamable HTTP spec:
        # If client provides session ID but session doesn't exist, return 404
        if mcp_session_id:
            existing_session = await sessions.get(mcp_session_id)
            if not existing_session:
                raise HTTPException(
                    status_code=404, detail="Session not found. Please start a new session with InitializeRequest."
                )
            if existing_session.is_expired():
                await sessions.remove(mcp_session_id)
                _initialized_sessions.pop(mcp_session_id, None)
                raise HTTPException(
                    status_code=404, detail="Session expired. Please start a new session with InitializeRequest."
                )
            session = existing_session
            session.update_activity()
            await sessions.set(mcp_session_id, session)
        else:
            # Create new session only if no session ID provided
            session = await get_or_create_session(None, origin)

        session.authenticated = True  # Mark as authenticated
        session._auth_token = auth_token  # Store token for scope checks in tool handlers

        # Common response headers
        response_headers = {
            "MCP-Session-Id": session.session_id,
            "MCP-Protocol-Version": protocol_version,
            "Access-Control-Expose-Headers": "MCP-Session-Id, MCP-Protocol-Version",
        }

        # Handle GET request per MCP Streamable HTTP spec
        if request.method == "GET":
            # Per spec: server MUST return text/event-stream OR HTTP 405
            if accept and "text/event-stream" in accept:
                # track_connection=True: decrement happens when stream closes
                _sse_returned = True
                response = StreamingResponse(
                    generate_sse_events(session, track_connection=True),
                    media_type="text/event-stream",
                    headers={**response_headers, "Cache-Control": "no-cache", "Connection": "keep-alive"},
                )
                return response
            else:
                # Per MCP spec: GET without Accept: text/event-stream MUST return 405
                raise HTTPException(
                    status_code=405, detail="GET requires Accept: text/event-stream header for SSE stream"
                )

        # Handle POST request (JSON-RPC)
        elif request.method == "POST":
            try:
                body = await request.json()
            except json.JSONDecodeError:
                return JSONResponse(
                    content=create_error_response(None, MCP_ERRORS["PARSE_ERROR"], "Invalid JSON").dict(),
                    status_code=400,
                    headers=response_headers,
                )

            # Handle batch messages per MCP Streamable HTTP spec
            if isinstance(body, list):
                if not body:
                    return JSONResponse(
                        content=create_error_response(
                            None, MCP_ERRORS["INVALID_REQUEST"], "Empty batch request"
                        ).dict(),
                        status_code=400,
                        headers=response_headers,
                    )
                if len(body) > MAX_BATCH_SIZE:
                    return JSONResponse(
                        content=create_error_response(
                            None, MCP_ERRORS["INVALID_REQUEST"], f"Batch too large (max {MAX_BATCH_SIZE})"
                        ).dict(),
                        status_code=400,
                        headers=response_headers,
                    )

                # Check if batch contains any requests
                has_requests = any(is_json_rpc_request(item) if isinstance(item, dict) else False for item in body)

                if not has_requests:
                    # Process all notifications before returning 202
                    for item in body:
                        if isinstance(item, dict) and is_json_rpc_notification(item):
                            method = item.get("method", "")
                            params = item.get("params", {})
                            await process_mcp_notification(method, params, session)
                    return Response(status_code=202, headers=response_headers)

                # Process requests in batch
                responses = []
                for item in body:
                    # Process notifications but don't add to responses
                    if isinstance(item, dict) and is_json_rpc_notification(item):
                        method = item.get("method", "")
                        params = item.get("params", {})
                        await process_mcp_notification(method, params, session)
                        continue
                    # Skip responses
                    if isinstance(item, dict) and is_json_rpc_response(item):
                        continue
                    try:
                        if not isinstance(item, dict):
                            raise TypeError(f"Expected dict, got {type(item).__name__}")
                        mcp_request = MCPRequest(**item)
                        resp = await process_mcp_request(mcp_request, session)
                        responses.append(resp.dict())
                    except (ValidationError, TypeError) as e:
                        responses.append(
                            create_error_response(
                                item.get("id") if isinstance(item, dict) else None,
                                MCP_ERRORS["INVALID_REQUEST"],
                                f"Invalid request format: {e}",
                            ).dict()
                        )

                return JSONResponse(content=responses, headers=response_headers)

            # Handle single message
            if isinstance(body, dict):
                # Notifications and responses return 202 Accepted
                if is_json_rpc_notification(body):
                    # Process the notification (no response)
                    method = body.get("method", "")
                    params = body.get("params", {})
                    await process_mcp_notification(method, params, session)
                    logger.debug(f"Processed notification: {method}")
                    return Response(status_code=202, headers=response_headers)
                elif is_json_rpc_response(body):
                    # Client sending a response - just acknowledge
                    return Response(status_code=202, headers=response_headers)

            # Validate JSON-RPC request
            try:
                mcp_request = MCPRequest(**body) if isinstance(body, dict) else None
            except ValidationError as e:
                return JSONResponse(
                    content=create_error_response(
                        None, MCP_ERRORS["INVALID_REQUEST"], f"Invalid MCP request: {str(e)}"
                    ).dict(),
                    status_code=400,
                    headers=response_headers,
                )

            # Process the request
            if mcp_request:
                mcp_response = await process_mcp_request(mcp_request, session)

                # Check if client accepts SSE for streaming response
                # (For long-running operations, we could upgrade to SSE here)
                if accept and "text/event-stream" in accept:
                    # Optional: Stream the response via SSE for long operations
                    # For now, return JSON response
                    return JSONResponse(content=mcp_response.dict(), headers=response_headers)
                else:
                    # Standard JSON response
                    return JSONResponse(content=mcp_response.dict(), headers=response_headers)
            else:
                return JSONResponse(
                    content=create_error_response(None, MCP_ERRORS["INVALID_REQUEST"], "Invalid request format").dict(),
                    status_code=400,
                    headers=response_headers,
                )

        else:
            raise HTTPException(status_code=405, detail="Method not allowed")

    except HTTPException as exc:
        _status_code = exc.status_code
        raise
    except Exception as e:
        _status_code = 500
        logger.error(f"MCP endpoint error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

    finally:
        # REQUEST_COUNT is already tracked by the monitoring middleware — no need to duplicate here.
        # Only decrement for non-SSE responses; SSE generator handles its own decrement.
        if not _sse_returned:
            ACTIVE_CONNECTIONS.dec()


@app.delete("/mcp")
async def close_mcp_session(
    mcp_session_id: str = Header(..., alias="MCP-Session-Id"), authorization: str = Header(None)
):
    """
    Close MCP session explicitly (2025-11-25 spec).
    Allows clients to cleanly terminate sessions.
    """
    # Use the same auth logic as other endpoints (respects authless mode)
    await verify_authentication(authorization, config)

    # Remove session
    existing = await sessions.get(mcp_session_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Session not found")
    await sessions.remove(mcp_session_id)
    _initialized_sessions.pop(mcp_session_id, None)
    logger.info(f"Session {mcp_session_id} closed via DELETE")
    return Response(status_code=204)  # No content


@app.get("/health")
async def health_check():
    """Health check endpoint with detailed status."""
    try:
        # Test Wazuh connectivity
        wazuh_status = "healthy"
        try:
            await wazuh_client.get_manager_info()
        except Exception:
            wazuh_status = "unhealthy"

        # Test Wazuh Indexer connectivity (if configured)
        indexer_status = "not_configured"
        if wazuh_client._indexer_client:
            try:
                health = await wazuh_client._indexer_client.health_check()
                if health.get("status") in ("green", "yellow"):
                    indexer_status = "healthy"
                elif health.get("status") == "red":
                    indexer_status = "degraded"
                else:
                    indexer_status = "unknown"
            except Exception:
                indexer_status = "unhealthy"

        # Check session count
        all_sessions = await sessions.get_all()
        active_sessions = len([s for s in all_sessions.values() if not s.is_expired()])

        # Build auth info
        auth_info = {
            "mode": config.AUTH_MODE,
            "bearer_enabled": config.is_bearer,
            "oauth_enabled": config.is_oauth,
            "authless": config.is_authless,
        }
        if config.is_oauth:
            auth_info["oauth_dcr"] = config.OAUTH_ENABLE_DCR
            auth_info["oauth_endpoints"] = ["/oauth/authorize", "/oauth/token", "/oauth/register"]
            auth_info["oauth_discovery"] = "/.well-known/oauth-authorization-server"

        # Determine overall status from component health
        if wazuh_status != "healthy":
            overall_status = "degraded"
        elif isinstance(indexer_status, str) and indexer_status.startswith("unhealthy"):
            overall_status = "degraded"
        else:
            overall_status = "healthy"

        status_code = 200 if overall_status == "healthy" else 503
        return JSONResponse(
            content={
                "status": overall_status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": __version__,
                "mcp_protocol_version": MCP_PROTOCOL_VERSION,
                "supported_protocol_versions": SUPPORTED_PROTOCOL_VERSIONS,
                "transport": {
                    "streamable_http": "enabled",
                    "legacy_sse": "enabled",
                },
                "authentication": auth_info,
                "services": {"wazuh_manager": wazuh_status, "wazuh_indexer": indexer_status, "mcp": "healthy"},
                "vulnerability_tools": {
                    "available": wazuh_client._indexer_client is not None,
                    "note": (
                        "Vulnerability tools require Wazuh Indexer (4.8.0+). Set WAZUH_INDEXER_HOST to enable."
                        if not wazuh_client._indexer_client
                        else "Wazuh Indexer configured"
                    ),
                },
                "metrics": {"active_sessions": active_sessions, "total_sessions": len(all_sessions)},
                "endpoints": {
                    "recommended": "/mcp (Streamable HTTP - 2025-11-25)",
                    "legacy": "/sse (SSE only)",
                    "authentication": (
                        "/auth/token" if config.is_bearer else ("/oauth/token" if config.is_oauth else None)
                    ),
                    "monitoring": ["/health", "/metrics"],
                },
            },
            status_code=status_code,
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            content={"status": "unhealthy", "timestamp": datetime.now(timezone.utc).isoformat()},
            status_code=503,
        )


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

    from wazuh_mcp_server.monitoring import REGISTRY

    return Response(content=generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


# OAuth 2.0 Discovery Endpoint (RFC 8414)
@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata(request: Request):
    """
    OAuth 2.0 Authorization Server Metadata endpoint.
    Required for Claude Desktop OAuth integration.
    """
    global _oauth_manager
    if not config.is_oauth or not _oauth_manager:
        raise HTTPException(status_code=404, detail="OAuth not enabled. Set AUTH_MODE=oauth to enable.")

    return JSONResponse(_oauth_manager.get_metadata(request))


# Authentication endpoint for API key validation
@app.post("/auth/token")
async def get_auth_token(request: Request):
    """Get JWT token using API key.

    Accepts API key in request body as JSON: {"api_key": "wazuh_..."}
    Validates against configured API keys (MCP_API_KEY env var or auto-generated).
    """
    try:
        body = await request.json()
        api_key = body.get("api_key")

        if not api_key:
            raise HTTPException(status_code=400, detail="API key required")

        # Validate API key format
        if not isinstance(api_key, str) or not api_key.startswith("wazuh_"):
            raise HTTPException(status_code=401, detail="Invalid API key format")

        # Validate against auth_manager (handles MCP_API_KEY env var and auto-generated keys)
        from wazuh_mcp_server.auth import auth_manager

        if not auth_manager.validate_api_key(api_key):
            raise HTTPException(status_code=401, detail="Invalid API key")

        # Create JWT token with safe payload (no API key exposure)
        token = create_access_token(
            data={
                "sub": "wazuh_mcp_user",
                "iat": datetime.now(timezone.utc).timestamp(),
                "scope": "wazuh:read wazuh:write",
            },
            secret_key=config.AUTH_SECRET_KEY,
        )

        return {"access_token": token, "token_type": "bearer", "expires_in": 86400}  # 24 hours

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    except HTTPException:
        raise  # Re-raise HTTP exceptions as-is
    except Exception as e:
        logger.error(f"Token generation error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


if __name__ == "__main__":
    import uvicorn

    config = get_config()

    uvicorn.run(app, host=config.MCP_HOST, port=config.MCP_PORT, log_level=config.LOG_LEVEL.lower(), access_log=True)
