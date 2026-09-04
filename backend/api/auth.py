from __future__ import annotations

from fastapi import Header, HTTPException, status

from backend.security.authenticated_user import AuthenticatedUser
from backend.security.jwt import TokenError, verify_access_token


def require_authenticated_user(
    authorization: str | None = Header(default=None),
) -> AuthenticatedUser:
    """
    Authenticate an API request using an access-token Bearer credential.

    Security boundary:
    - Identity comes exclusively from the verified JWT.
    - Request-supplied user IDs are never trusted here.
    - Session/revocation checks remain outside JWT verification.
    """

    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if authorization is None:
        raise unauthorized

    scheme, separator, credentials = authorization.partition(" ")

    if (
        not separator
        or scheme.lower() != "bearer"
        or not credentials.strip()
    ):
        raise unauthorized

    try:
        verified = verify_access_token(credentials.strip())
    except TokenError as exc:
        raise unauthorized from exc

    return verified.user
