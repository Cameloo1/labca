from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.config import get_settings
from app.dependencies import get_db

router = APIRouter(tags=["home"])

templates = Jinja2Templates(directory="app/templates")
settings = get_settings()


@router.get("/", response_class=HTMLResponse)
def get_home(
    request: Request,
    _db: Session = Depends(get_db),  # ensures dependency wiring for future DB usage
) -> HTMLResponse:
    return templates.TemplateResponse(
        "home.html",
        {
            "request": request,
            "app_name": settings.APP_NAME,
        },
    )
