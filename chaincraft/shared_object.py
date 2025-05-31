# shared_object.py

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from .shared_message import SharedMessage


class SharedObjectException(Exception):
    pass


class SharedObject(ABC):
    @abstractmethod
    def is_valid(self, message: SharedMessage) -> bool:
        raise SharedObjectException("is_valid method not implemented")

    @abstractmethod
    def add_message(self, message: SharedMessage) -> None:
        raise SharedObjectException("add_message method not implemented")

    @abstractmethod
    def is_merkelized(self) -> bool:
        raise SharedObjectException("is_merkelized method not implemented")

    @abstractmethod
    def get_latest_digest(self) -> str:
        raise SharedObjectException("get_latest_digest method not implemented")

    @abstractmethod
    def has_digest(self, hash_digest: str) -> bool:
        raise SharedObjectException("has_digest method not implemented")

    @abstractmethod
    def is_valid_digest(self, hash_digest: str) -> bool:
        raise SharedObjectException("is_valid_digest method not implemented")

    @abstractmethod
    def add_digest(self, hash_digest: str) -> bool:
        raise SharedObjectException("add_digest method not implemented")

    @abstractmethod
    def gossip_object(self, digest) -> List[SharedMessage]:
        raise SharedObjectException("gossip_object method not implemented")

    @abstractmethod
    def get_messages_since_digest(self, digest: str) -> List[SharedMessage]:
        raise SharedObjectException("get_messages_since_digest method not implemented")
