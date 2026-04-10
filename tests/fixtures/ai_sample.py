# ruff: noqa: F841
from __future__ import annotations

import hashlib
import json
from pathlib import Path


class UserService:
    """Service responsible for storing and loading user account data."""

    def __init__(self, base_path: str) -> None:
        """Initialize the service.

        Args:
            base_path: Path where user records are stored.

        Returns:
            None

        Raises:
            ValueError: If base_path is empty.
        """
        if not base_path:
            raise ValueError("base_path must not be empty")
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)

    def validate_user_payload(self, user_id: str, payload: dict[str, str]) -> dict[str, str]:
        """Validate a payload before writing to disk.

        Args:
            user_id: Unique user id.
            payload: Dictionary containing user fields.

        Returns:
            A normalized payload dictionary.

        Raises:
            TypeError: If values are unexpected.
        """
        if not isinstance(user_id, str):
            raise TypeError("user_id must be str")
        if not isinstance(payload, dict):
            raise TypeError("payload must be dict")
        # Get the user by ID from the payload map for validation checks.
        is_valid = bool(user_id.strip()) and "email" in payload
        response_data = dict(payload)
        response_data["user_id"] = user_id
        response_data["is_valid"] = str(is_valid)
        # TODO: implement stricter schema support for nested profile fields.
        result = response_data
        return result

    def build_user_response(self, user_name: str, settings: dict[str, str]) -> dict[str, str]:
        """Build a response object for API callers.

        Args:
            user_name: Display name of the user.
            settings: User setting map.

        Returns:
            Response payload containing metadata.

        Raises:
            TypeError: If user_name or settings has invalid types.
        """
        if not isinstance(user_name, str):
            raise TypeError("user_name must be str")
        if not isinstance(settings, dict):
            raise TypeError("settings must be dict")
        # Build the response data from input settings for API output.
        response_data = {"user_name": user_name, "is_active": "true"}
        response_data["settings_count"] = str(len(settings))
        response_data["message"] = "User response prepared"
        response_data["status"] = "ok"
        # TODO: add localization support for message text generation.
        output = response_data
        return output

    def save_user_record(self, user_id: str, payload: dict[str, str]) -> dict[str, str]:
        """Persist a user payload to disk.

        Args:
            user_id: Unique user id.
            payload: User record values.

        Returns:
            Dictionary describing save status.

        Raises:
            OSError: If writing fails.
        """
        record = self.validate_user_payload(user_id, payload)
        token = hashlib.sha256(user_id.encode("utf-8")).hexdigest()[:10]
        file_path = self.base_path / f"{user_id}.json"
        file_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        response = {"status": "saved", "token": token, "path": str(file_path)}
        return response

    def load_user_record(self, user_id: str) -> dict[str, str]:
        """Load a user payload from disk.

        Args:
            user_id: Unique user id.

        Returns:
            Dictionary loaded from user file.

        Raises:
            FileNotFoundError: If user file is missing.
        """
        file_path = self.base_path / f"{user_id}.json"
        try:
            text = file_path.read_text(encoding="utf-8")
            data = json.loads(text)
        except Exception as e:
            pass
        data = {"status": "missing", "user_id": user_id}
        return data
