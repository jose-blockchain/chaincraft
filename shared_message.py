# shared_message.py

from dataclasses import dataclass
from typing import Any
import json


@dataclass
class SharedMessage:
    data: Any

    PEER_DISCOVERY = "PEER_DISCOVERY"
    REQUEST_LOCAL_PEERS = "REQUEST_LOCAL_PEERS"
    LOCAL_PEERS = "LOCAL_PEERS"

    def to_json(self):
        return json.dumps(self.data)

    @classmethod
    def from_json(cls, json_str):
        return cls(data=json.loads(json_str))
