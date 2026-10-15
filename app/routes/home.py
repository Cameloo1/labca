from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.config import get_settings
from app.dependencies import get_db
from app.templating import templates

router = APIRouter(tags=["home"])

settings = get_settings()


@router.get("/", response_class=HTMLResponse)
def get_home(
    request: Request,
    _db: Session = Depends(get_db),  # ensures dependency wiring for future DB usage
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "home.html",
        {
            "request": request,
            "app_name": settings.APP_NAME,
        },
    )
