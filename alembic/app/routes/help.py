from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.templating import get_templates

router = APIRouter(tags=["help"])

templates = get_templates()


@router.get("/help", response_class=HTMLResponse)
def help_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        "help.html",
        {"request": request},
    )
