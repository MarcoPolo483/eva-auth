"""Main FastAPI application."""

import secrets
from contextlib import asynccontextmanager

import redis.asyncio as redis
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from eva_auth.config import settings
from eva_auth.middleware import AuthMiddleware
from eva_auth.routers import auth_router, health_router


# Redis connection
redis_client: redis.Redis | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup: Initialize Redis connection
    global redis_client
    redis_client = redis.from_url(
        settings.redis_url,
        password=settings.redis_password if settings.redis_password else None,
        db=settings.redis_db,
        encoding="utf-8",
        decode_responses=True,
    )
    
    yield
    
    # Shutdown: Close Redis connection
    if redis_client:
        await redis_client.close()


# Create FastAPI app
app = FastAPI(
    title="EVA Authentication & Authorization Service",
    description="OAuth 2.0, JWT validation, RBAC, and session management for EVA Suite",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentication middleware (only for non-public routes)
if settings.enable_mock_auth:
    app.add_middleware(AuthMiddleware)

# Include routers
app.include_router(health_router, tags=["Health"])
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": "An unexpected error occurred",
            "detail": str(exc) if settings.environment == "development" else None,
        },
    )


def get_redis_client() -> redis.Redis:
    """Get Redis client dependency."""
    if redis_client is None:
        raise RuntimeError("Redis client not initialized")
    return redis_client
