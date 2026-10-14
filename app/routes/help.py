from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter(tags=["help"])

templates = Jinja2Templates(directory="app/templates")


@router.get("/help", response_class=HTMLResponse)
def help_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "help.html",
        {"request": request},
    )
