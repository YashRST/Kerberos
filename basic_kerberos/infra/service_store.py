from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Optional
from ..core.models import ServiceRecord

@dataclass
class InMemoryServiceStore:
    _services: Dict[str, ServiceRecord] = field(default_factory=dict)

    def add(self, service: ServiceRecord) -> None:
        self._services[service.name] = service

    def get(self, service_name: str) -> Optional[ServiceRecord]:
        return self._services.get(service_name)
