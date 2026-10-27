from dataclasses import dataclass
from typing import Literal

Variant = Literal["insecure", "protected"]


@dataclass(frozen=True)
class LoginResult:
    status: Literal["success", "invalid", "waiting", "locked"]
    password_checked: bool
    retry_after: float = 0.0

    @property
    def blocked(self) -> bool:
        return self.status in {"waiting", "locked"}
