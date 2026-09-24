from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4


@dataclass
class SessionRecord:
    """
    Domain representation of an authenticated Eldorado session.

    Session state is authentication infrastructure. It does not grant
    authorization by itself; authorization remains enforced by the
    application and PostgreSQL RLS boundaries.
    """

    user_id: UUID
    token_family_id: UUID

    id: UUID = field(default_factory=uuid4)

    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    last_used_at: datetime | None = None
    expires_at: datetime | None = None

    revoked_at: datetime | None = None
    reuse_detected_at: datetime | None = None

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        if not isinstance(self.user_id, UUID):
            raise TypeError("user_id must be a UUID.")

        if not isinstance(self.token_family_id, UUID):
            raise TypeError("token_family_id must be a UUID.")

        if not isinstance(self.id, UUID):
            raise TypeError("id must be a UUID.")

        self._require_timezone_aware(
            self.created_at,
            "created_at",
        )

        if self.last_used_at is not None:
            self._require_timezone_aware(
                self.last_used_at,
                "last_used_at",
            )

            if self.last_used_at < self.created_at:
                raise ValueError(
                    "last_used_at cannot be before created_at."
                )

        if self.expires_at is None:
            raise ValueError("expires_at is required.")

        self._require_timezone_aware(
            self.expires_at,
            "expires_at",
        )

        if self.expires_at <= self.created_at:
            raise ValueError(
                "expires_at must be after created_at."
            )

        if self.revoked_at is not None:
            self._require_timezone_aware(
                self.revoked_at,
                "revoked_at",
            )

            if self.revoked_at < self.created_at:
                raise ValueError(
                    "revoked_at cannot be before created_at."
                )

        if self.reuse_detected_at is not None:
            self._require_timezone_aware(
                self.reuse_detected_at,
                "reuse_detected_at",
            )

            if self.reuse_detected_at < self.created_at:
                raise ValueError(
                    "reuse_detected_at cannot be before created_at."
                )

    @staticmethod
    def _require_timezone_aware(
        value: datetime,
        field_name: str,
    ) -> None:
        if value.tzinfo is None:
            raise ValueError(
                f"{field_name} must be timezone-aware."
            )

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None


@dataclass
class RefreshTokenRecord:
    """
    Domain representation of a persisted refresh-token record.

    Only the cryptographic token hash is stored. The plaintext refresh
    credential must never be persisted in this record or the database.
    """

    session_id: UUID
    token_hash: str

    id: UUID = field(default_factory=uuid4)

    issued_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    expires_at: datetime | None = None

    consumed_at: datetime | None = None
    replaced_by_id: UUID | None = None

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        if not isinstance(self.session_id, UUID):
            raise TypeError("session_id must be a UUID.")

        if not isinstance(self.id, UUID):
            raise TypeError("id must be a UUID.")

        if not isinstance(self.token_hash, str):
            raise TypeError("token_hash must be a string.")

        if not self.token_hash.strip():
            raise ValueError("token_hash cannot be blank.")

        self._require_timezone_aware(
            self.issued_at,
            "issued_at",
        )

        if self.expires_at is None:
            raise ValueError("expires_at is required.")

        self._require_timezone_aware(
            self.expires_at,
            "expires_at",
        )

        if self.expires_at <= self.issued_at:
            raise ValueError(
                "expires_at must be after issued_at."
            )

        if self.consumed_at is not None:
            self._require_timezone_aware(
                self.consumed_at,
                "consumed_at",
            )

            if self.consumed_at < self.issued_at:
                raise ValueError(
                    "consumed_at cannot be before issued_at."
                )

        if self.replaced_by_id == self.id:
            raise ValueError(
                "replaced_by_id cannot reference the same token."
            )

        if self.replaced_by_id is not None:
            if not isinstance(self.replaced_by_id, UUID):
                raise TypeError(
                    "replaced_by_id must be a UUID."
                )

    @staticmethod
    def _require_timezone_aware(
        value: datetime,
        field_name: str,
    ) -> None:
        if value.tzinfo is None:
            raise ValueError(
                f"{field_name} must be timezone-aware."
            )

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at

    @property
    def is_consumed(self) -> bool:
        return self.consumed_at is not None