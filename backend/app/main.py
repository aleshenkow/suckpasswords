import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse

from .routers import admin, auth, backup, entries, folders, ldap, smtp
from .startup import run_startup

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

UI_FILE = Path(__file__).with_name("ui.html")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    run_startup()
    yield


app = FastAPI(title="SuckPasswords", lifespan=lifespan)

for _module in (auth, folders, entries, admin, ldap, smtp, backup):
    app.include_router(_module.router)


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    if not UI_FILE.exists():
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="UI file missing")
    return HTMLResponse(content=UI_FILE.read_text(encoding="utf-8"))


@app.get("/health", include_in_schema=False)
def health() -> dict[str, str]:
    return {"status": "ok"}
