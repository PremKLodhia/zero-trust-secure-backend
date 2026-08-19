import os
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse
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
    
    Implements WebAuthn passkey authentication, OIDC federated login, rotating refresh tokens with reuse detection, OPA fail-secure authorization, and Vault envelope encryption.
    """
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self';"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

app.include_router(auth_router)
app.include_router(cases_router)
app.include_router(users_router)
app.include_router(audit_router)

@app.get("/", response_class=HTMLResponse, tags=["WebAuthn UI"])
def index():
    html_path = os.path.join(os.path.dirname(__file__), "..", "static_index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>Zero-Trust Backend Running</h1><p><a href='/docs'>Swagger API Docs</a></p>")

@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "auth_enforcement": "active"
    }
