# shared_object.py

from abc import ABC, abstractmethod
from typing import List

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

    def is_merkelized(self) -> bool:
        return False

    def get_latest_digest(self) -> str:
        return ""

    def has_digest(self, hash_digest: str) -> bool:
        return False

    def is_valid_digest(self, hash_digest: str) -> bool:
        return False

    def add_digest(self, hash_digest: str) -> bool:
        return False

    def gossip_object(self, digest) -> List[SharedMessage]:
        return []

    def get_messages_since_digest(self, digest: str) -> List[SharedMessage]:
        return []
