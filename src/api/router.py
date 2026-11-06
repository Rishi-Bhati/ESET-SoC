from fastapi import APIRouter
from src.api.webhook import router as webhook_router
from src.api.health import router as health_router
from src.api.status import router as status_router
from src.api.dashboard import router as dashboard_router
from src.api.ai_visibility import router as ai_visibility_router
from src.api.client_auth import router as client_auth_router
from src.api.client import router as client_router
from src.api.client_reports import router as client_reports_router
from src.api.recommendations import router as recommendations_router
from src.api.reports import router as reports_router
from src.api.portal_admin import router as portal_admin_router
from src.api.portal_settings import router as portal_settings_router

api_router = APIRouter()

api_router.include_router(webhook_router)
api_router.include_router(health_router)
api_router.include_router(status_router)
api_router.include_router(dashboard_router)
api_router.include_router(ai_visibility_router)
api_router.include_router(client_auth_router)
api_router.include_router(client_router)
api_router.include_router(client_reports_router)
api_router.include_router(recommendations_router)
api_router.include_router(reports_router)
api_router.include_router(portal_admin_router)
api_router.include_router(portal_settings_router)
