from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .db import get_db
from .models import ApiToken
from .services.api_token_service import validate_token


def get_api_token(
    request: Request,
    db: Session = Depends(get_db),
) -> ApiToken:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    raw_token = auth_header.split(" ", 1)[1].strip()
    token = validate_token(raw_token, db)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API token is invalid or expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token


__all__ = ["get_db", "get_api_token"]
