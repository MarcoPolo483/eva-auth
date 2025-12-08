"""Routers for eva-auth."""

from eva_auth.routers.auth import router as auth_router
from eva_auth.routers.health import router as health_router

__all__ = ["auth_router", "health_router"]
