from fastapi import APIRouter
from src.api.webhook import router as webhook_router
from src.api.health import router as health_router
from src.api.status import router as status_router
from src.api.dashboard import router as dashboard_router
from src.api.ai_visibility import router as ai_visibility_router

api_router = APIRouter()

api_router.include_router(webhook_router)
api_router.include_router(health_router)
api_router.include_router(status_router)
api_router.include_router(dashboard_router)
api_router.include_router(ai_visibility_router)
