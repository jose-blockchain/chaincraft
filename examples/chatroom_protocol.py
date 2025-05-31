import time
import json
from typing import List, Dict, Set

from shared_object import SharedObject, SharedObjectException
from shared_message import SharedMessage
from chaincraft.crypto_primitives.sign import ECDSASignaturePrimitive


def verify_signature(
    public_key_pem: str, 
    payload_str: str, 
    signature_hex: str
) -> bool:
    """
    Verifies the ECDSA signature for the given payload string.

    - `public_key_pem`: The signer's public key in PEM format.
    - `payload_str`: The JSON-serialized data (minus the signature field).
    - `signature_hex`: The hex-encoded ECDSA signature.
    """
    try:
        ecdsa = ECDSASignaturePrimitive()
        ecdsa.load_pub_key_from_pem(public_key_pem)
        signature_bytes = bytes.fromhex(signature_hex)
        return ecdsa.verify(payload_str.encode("utf-8"), signature_bytes)
    except Exception:
        return False


class ChatroomObject(SharedObject):
    """
    A non-merkelized chatroom protocol.
    Manages multiple chatrooms in memory:

      chatrooms: {
        <chatroom_name>: {
          "admin": <public_key_pem of admin>,
          "members": set of <public_key_pem>,
          "messages": [
              { "public_key_pem": str, "text": str, "timestamp": float }, ...
          ]
        },
        ...
      }
    """

    def __init__(self):
        self.chatrooms: Dict[str, Dict] = {}

    def is_valid(self, message: SharedMessage) -> bool:
        """
        Validates the message:
          1) Must be a dict with required fields:
             ["message_type", "chatroom_name", "public_key_pem", "signature", "timestamp"].
          2) Timestamp must be within ±15 seconds of local time.
          3) We verify ECDSA signature with the included public_key_pem.
          4) Additional logic based on message_type:
             - CREATE_CHATROOM => name must be new
             - REQUEST_JOIN    => chatroom must exist, user not already a member
             - ACCEPT_MEMBER   => only the admin can accept
             - POST_MESSAGE    => only an accepted member or the admin can post
        """
        data = message.data
        if not isinstance(data, dict):
            return False

        required = ["message_type", "chatroom_name", "public_key_pem", "signature", "timestamp"]
        for field in required:
            if field not in data:
                return False

        # 1) Check timestamp ±15s
        now = time.time()
        msg_time = float(data["timestamp"])
        if abs(now - msg_time) > 15:
            return False

        # 2) Allowed message types
        msg_type = data["message_type"]
        if msg_type not in ("CREATE_CHATROOM", "REQUEST_JOIN", "ACCEPT_MEMBER", "POST_MESSAGE"):
            return False

        # 3) Verify ECDSA signature
        #    We'll create a JSON payload of all fields except "signature" 
        #    and compare to the public_key_pem field
        signature_hex = data["signature"]
        temp_dict = dict(data)
        del temp_dict["signature"]
        payload_str = json.dumps(temp_dict, sort_keys=True)

        pub_key_pem = data["public_key_pem"]
        if not verify_signature(pub_key_pem, payload_str, signature_hex):
            return False

        # 4) Additional logic checks per message type
        cname = data["chatroom_name"]
        if msg_type == "CREATE_CHATROOM":
            # Must be a new name
            if cname in self.chatrooms:
                return False

        elif msg_type == "REQUEST_JOIN":
            # Chatroom must exist
            if cname not in self.chatrooms:
                return False
            # The user shouldn't already be a member
            if pub_key_pem in self.chatrooms[cname]["members"]:
                return False

        elif msg_type == "ACCEPT_MEMBER":
            # Chatroom must exist
            if cname not in self.chatrooms:
                return False
            # The admin alone can accept
            if pub_key_pem != self.chatrooms[cname]["admin"]:
                return False
            # Must specify the "requester_key_pem" to accept
            if "requester_key_pem" not in data:
                return False
            # The requester should not already be in members
            if data["requester_key_pem"] in self.chatrooms[cname]["members"]:
                return False

        elif msg_type == "POST_MESSAGE":
            # Must exist
            if cname not in self.chatrooms:
                return False
            # Must be admin or an accepted member
            admin_key = self.chatrooms[cname]["admin"]
            members = self.chatrooms[cname]["members"]
            if (pub_key_pem != admin_key) and (pub_key_pem not in members):
                return False
            # Must have a "text" field
            if "text" not in data:
                return False

        return True

    def add_message(self, message: SharedMessage) -> None:
        data = message.data
        msg_type = data["message_type"]
        cname = data["chatroom_name"]

        if msg_type == "CREATE_CHATROOM":
            self.chatrooms[cname] = {
                "admin": data["public_key_pem"],
                "members": set(),
                "messages": []
            }
            # Also store it in the messages array if you want to see it in the CLI
            self.chatrooms[cname]["messages"].append(data)

        elif msg_type == "REQUEST_JOIN":
            # Currently, you do nothing, so the CLI never sees it
            # FIX: append to chat messages so the CLI background loop can auto-accept:
            self.chatrooms[cname]["messages"].append(data)

        elif msg_type == "ACCEPT_MEMBER":
            self.chatrooms[cname]["members"].add(data["requester_key_pem"])
            # Also store it for the CLI to see
            self.chatrooms[cname]["messages"].append(data)

        elif msg_type == "POST_MESSAGE":
            # This is already appended to messages
            self.chatrooms[cname]["messages"].append(data)
            
    # ---------------------------------------------------
    # Non-merkelized stubs below
    # ---------------------------------------------------
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
