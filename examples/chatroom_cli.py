import argparse
import sys
import time
import json
import threading
import random

from chaincraft import ChaincraftNode
from examples.chatroom_protocol import ChatroomObject
from crypto_primitives.ecdsa_sign import ECDSASignaturePrimitive

# ANSI color codes + some emojis
COLOR_RESET = "\033[0m"
COLOR_CYAN = "\033[96m"
COLOR_MAGENTA = "\033[95m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BOLD = "\033[1m"

CHECK_EMOJI = "✅"
CHAT_EMOJI = "💬"
WARN_EMOJI = "⚠️ "
STAR_EMOJI = "✨"


class ChatroomCLI:
    def __init__(self, port=None, peer=None, debug=False):
        """
        - local_discovery=True ensures automatic local peer exchange.
        - We'll do 'auto-accept' of REQUEST_JOIN if we're admin.
        """
        # Create ephemeral ECDSA key for signing
        self.ecdsa = ECDSASignaturePrimitive()
        self.ecdsa.generate_key()
        self.pub_pem = self.ecdsa.get_public_pem()

        # Create a chaincraft node with local discovery
        self.node = ChaincraftNode(
            persistent=False,
            debug=debug,
            port=port if port else random.randint(10000, 60000),
            local_discovery=True
        )
        self.chatroom_object = ChatroomObject()
        self.node.add_shared_object(self.chatroom_object)
        self.node.start()

        # Connect to a known peer (optional)
        if peer:
            host, p = peer.split(":")
            # Connect with discovery
            self.node.connect_to_peer(host, int(p), discovery=True)
            # Also local peer request
            self.node.connect_to_peer_locally(host, int(p))

        print(f"{STAR_EMOJI} {COLOR_BOLD}Chatroom CLI started at {self.node.host}:{self.node.port}{COLOR_RESET}")
        print(f"Your ephemeral ECDSA public key (PEM):\n{COLOR_CYAN}{self.pub_pem}{COLOR_RESET}\n")
        print(f"Type '{COLOR_BOLD}/help{COLOR_RESET}' to see commands.")

        # We'll keep an internal 'current_chatroom' for quick "/msg" usage
        self.current_chatroom = None

        # For printing new messages
        self.last_msg_count = {}  # track how many messages we've seen per chat
        self.stop_print_thread = False
        self.print_thread = threading.Thread(target=self._background_printer, daemon=True)
        self.print_thread.start()

    def _background_printer(self):
        """
        Periodically checks for new chat messages. 
        Also auto-accepts any REQUEST_JOIN if we're the admin for that room.
        """
        while not self.stop_print_thread:
            for cname, data in self.chatroom_object.chatrooms.items():
                msg_list = data["messages"]
                old_count = self.last_msg_count.get(cname, 0)
                new_count = len(msg_list)

                if new_count > old_count:
                    for i in range(old_count, new_count):
                        msg = msg_list[i]
                        # Print new messages
                        self._maybe_print_chat_message(cname, msg)
                        # Also auto-accept any join requests if we're admin
                        self._maybe_auto_accept(cname, msg)

                    self.last_msg_count[cname] = new_count

            time.sleep(1.0)

    def _maybe_print_chat_message(self, chatroom_name, msg):
        """
        If the message is POST_MESSAGE, print it in a fancy way.
        Also if it's something else (like user joined?), we can highlight it.
        """
        mtype = msg.get("message_type")
        user_key = msg.get("public_key_pem", "")[:20].replace("\n", "") + "..."
        text = msg.get("text", "")

        # We'll only "print" text for "POST_MESSAGE" (others could be quiet)
        if mtype == "POST_MESSAGE":
            print(
                f"\n{CHAT_EMOJI} {COLOR_YELLOW}[{chatroom_name}]{COLOR_RESET} "
                f"{COLOR_GREEN}{user_key}{COLOR_RESET}: "
                f"{COLOR_MAGENTA}{text}{COLOR_RESET}"
            )
        elif mtype == "REQUEST_JOIN":
            # Show a small note
            print(f"\n{CHAT_EMOJI} {COLOR_YELLOW}[{chatroom_name}]{COLOR_RESET} " 
                  f"{COLOR_GREEN}{user_key}{COLOR_RESET} requested to join!")
        elif mtype == "ACCEPT_MEMBER":
            # Show acceptance
            who = msg.get("requester_key_pem", "")[:20].replace("\n", "") + "..."
            print(f"\n{CHECK_EMOJI} {COLOR_YELLOW}[{chatroom_name}]{COLOR_RESET}: "
                  f"User {COLOR_GREEN}{who}{COLOR_RESET} has been accepted by admin!")

    def _maybe_auto_accept(self, chatroom_name, msg):
        """
        If this node is the admin of `chatroom_name` and `msg` is a REQUEST_JOIN,
        auto-accept the user who requested.
        """
        mtype = msg.get("message_type")
        if mtype != "REQUEST_JOIN":
            return

        # check if we're admin of this chatroom
        admin_key = self.chatroom_object.chatrooms[chatroom_name]["admin"]
        if admin_key == self.pub_pem:
            # We are admin, let's accept automatically
            requester_key = msg["public_key_pem"]
            # If they're not already in 'members', do an ACCEPT_MEMBER
            members = self.chatroom_object.chatrooms[chatroom_name]["members"]
            if requester_key not in members:
                # build ACCEPT_MEMBER
                accept_msg = {
                    "message_type": "ACCEPT_MEMBER",
                    "chatroom_name": chatroom_name,
                    "public_key_pem": self.pub_pem,   # admin key
                    "requester_key_pem": requester_key
                }
                self._sign_and_broadcast(accept_msg)

    def close(self):
        self.stop_print_thread = True
        time.sleep(1.1)
        self.node.close()
        print(f"{WARN_EMOJI} Node closed. Goodbye!")

    def run_cli_loop(self):
        """
        Simple command loop: /create, /join, /msg, /rooms, /help, /quit
        (No /accept needed now that auto-accept is enabled.)
        """
        while True:
            try:
                line = input("> ").strip()
            except EOFError:
                break

            if not line:
                continue

            if line.startswith("/"):
                parts = line.split(" ", 1)
                cmd = parts[0].lower()

                if cmd == "/help":
                    self.print_help()
                elif cmd == "/quit":
                    print("Exiting...")
                    break
                elif cmd == "/rooms":
                    self.print_rooms()
                elif cmd == "/create":
                    if len(parts) < 2:
                        print("Usage: /create <chatroom_name>")
                        continue
                    cname = parts[1].strip()
                    self.create_chatroom(cname)
                elif cmd == "/join":
                    if len(parts) < 2:
                        print("Usage: /join <chatroom_name>")
                        continue
                    cname = parts[1].strip()
                    self.request_join(cname)
                elif cmd == "/msg":
                    if len(parts) < 2:
                        print("Usage: /msg <text>")
                        continue
                    text_msg = parts[1].strip()
                    self.post_message(text_msg)
                else:
                    print("Unknown command. Type /help.")
            else:
                # treat as message
                self.post_message(line)

        self.close()

    # -------------------------------------
    # Chatroom actions
    # -------------------------------------
    def create_chatroom(self, chatroom_name):
        data = {
            "message_type": "CREATE_CHATROOM",
            "chatroom_name": chatroom_name,
            "public_key_pem": self.pub_pem,
        }
        self._sign_and_broadcast(data)
        self.current_chatroom = chatroom_name
        print(f"{CHECK_EMOJI} Created chatroom '{chatroom_name}'. You are admin.")

    def request_join(self, chatroom_name):
        data = {
            "message_type": "REQUEST_JOIN",
            "chatroom_name": chatroom_name,
            "public_key_pem": self.pub_pem,
        }
        self._sign_and_broadcast(data)
        self.current_chatroom = chatroom_name
        print(f"{CHECK_EMOJI} Requested to join chatroom '{chatroom_name}'.")

    def post_message(self, text_msg):
        if not self.current_chatroom:
            print("No chatroom selected. Use /create or /join.")
            return
        data = {
            "message_type": "POST_MESSAGE",
            "chatroom_name": self.current_chatroom,
            "public_key_pem": self.pub_pem,
            "text": text_msg,
        }
        self._sign_and_broadcast(data)

    # -------------------------------------
    # Utility
    # -------------------------------------
    def _sign_and_broadcast(self, data_dict):
        if "timestamp" not in data_dict:
            data_dict["timestamp"] = time.time()
        data_dict.pop("signature", None)
        payload_str = json.dumps(data_dict, sort_keys=True)
        sig_bytes = self.ecdsa.sign(payload_str.encode("utf-8"))
        data_dict["signature"] = sig_bytes.hex()
        self.node.create_shared_message(data_dict)

    def print_help(self):
        print(f"{COLOR_BOLD}Commands:{COLOR_RESET}")
        print("/create <name>       Create chatroom (admin)")
        print("/join <name>         Request to join chatroom (auto-accepted by admin)")
        print("/msg <text>          Post a message (or just type text w/o slash)")
        print("/rooms               List known chatrooms")
        print("/help                Show this help")
        print("/quit                Exit")

    def print_rooms(self):
        if not self.chatroom_object.chatrooms:
            print("No chatrooms yet. Use /create <chatroom_name> or /join <chatroom_name>.")
            return
        print(f"{STAR_EMOJI} {COLOR_BOLD}Known chatrooms:{COLOR_RESET}")
        for cname, cdata in self.chatroom_object.chatrooms.items():
            admin_key = cdata["admin"]
            short_admin = admin_key[:20].replace("\n", "") + "..."
            members = cdata["members"]
            short_mems = [m[:20].replace("\n", "") + "..." for m in members]
            msg_count = len(cdata["messages"])
            print(
                f"  {COLOR_YELLOW}{cname}{COLOR_RESET} "
                f"(admin: {COLOR_CYAN}{short_admin}{COLOR_RESET}, "
                f"{len(members)} members, {msg_count} msgs)"
            )
            if short_mems:
                print(f"    members => {short_mems}")


def main():
    parser = argparse.ArgumentParser(description="Chaincraft Chatroom CLI (auto-accept joins).")
    parser.add_argument("--port", type=int, help="UDP port to bind this node to (default random)")
    parser.add_argument("--peer", type=str, help="host:port of a known peer to connect to")
    parser.add_argument("--debug", action="store_true", help="Enable node debug prints")
    args = parser.parse_args()

    cli = ChatroomCLI(port=args.port, peer=args.peer, debug=args.debug)
    try:
        cli.run_cli_loop()
    except KeyboardInterrupt:
        print("\nInterrupted. Bye!")
    finally:
        cli.close()


if __name__ == "__main__":
    main()
