from __future__ import annotations


def purge_refusal(
    environment: str | None,
    database_name: str,
    typed_name: str,
) -> str | None:
    """
    Decide whether destructive development cleanup may proceed.

    Returns a reason to refuse, or None when it is allowed. Fails
    closed: cleanup runs only when ELDORADO_ENV is explicitly
    'development' and the operator has retyped the exact name of the
    database they are connected to.
    """
    if (environment or "").strip().lower() != "development":
        return (
            "ELDORADO_ENV must be 'development' for destructive "
            "development cleanup."
        )

    if not database_name or typed_name != database_name:
        return (
            "the database name you typed does not match the "
            "connected database."
        )

    return None