from fastapi import FastAPI
from contextlib import asynccontextmanager
from src.config import settings
from src.database import engine, Base
from src.api.cases import router as cases_router
from src.api.users import router as users_router
from src.api.audit import router as audit_router
from src.api.auth import router as auth_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables on startup
    Base.metadata.create_all(bind=engine)
    yield

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    description="""
    ## Zero-Trust Secure Backend & Identity Threat Detection
    
    Implements WebAuthn passkey authentication, OIDC federated login, rotating refresh tokens with reuse detection, and append-only audit logging.
    """
)

app.include_router(auth_router)
app.include_router(cases_router)
app.include_router(users_router)
app.include_router(audit_router)

@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "auth_enforcement": "phase_3_authn_enabled"
    }
