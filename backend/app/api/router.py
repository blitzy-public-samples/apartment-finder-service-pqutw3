from fastapi import APIRouter
from backend.app.api.endpoints import auth, listings, filters, subscriptions

api_router = APIRouter()

# Include routers from different endpoints
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(listings.router, prefix="/listings", tags=["listings"])
api_router.include_router(filters.router, prefix="/filters", tags=["filters"])
api_router.include_router(subscriptions.router, prefix="/subscriptions", tags=["subscriptions"])