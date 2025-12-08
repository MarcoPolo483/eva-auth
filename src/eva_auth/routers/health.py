"""Health check router."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "eva-auth",
        "version": "0.1.0",
    }


@router.get("/ready")
async def readiness_check():
    """Readiness check endpoint."""
    # TODO: Check Redis and Cosmos DB connectivity
    return {
        "status": "ready",
        "service": "eva-auth",
    }
