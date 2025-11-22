from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Optional
from ..core.models import UserRecord

@dataclass
class InMemoryUserStore:
    _users: Dict[str, UserRecord] = field(default_factory=dict)

    def add(self, user: UserRecord) -> None:
        self._users[user.username] = user

    def get(self, username: str) -> Optional[UserRecord]:
        return self._users.get(username)
