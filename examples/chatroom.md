# Chatroom CLI Usage

## 1. Run Admin Node

In one terminal, from the root of the repo, run:

```bash
python -m examples.chatroom_cli --port 21001
```

This starts a Chaincraft node on port **21001**, creates an **ephemeral** ECDSA key, and displays:

```
✨ Chatroom CLI started at 127.0.0.1:21001
Your ephemeral ECDSA public key (PEM):
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
...
Type '/help' to see commands.
```

### Create a Chatroom

At the prompt, type:

```
/create Chaincraft
```

Output:
```
✅ Created chatroom 'Chaincraft'. You are admin.
```

Leave this terminal open. You’re now the **admin** of “Chaincraft,” with **auto-accept** enabled, so any new join requests will be accepted automatically.

---

## 2. Run Second Node

Open another terminal, from the root of the repo:

```bash
python -m examples.chatroom_cli --port 21002 --peer 127.0.0.1:21001
```

This node:
- Binds to port **21002**
- Connects to the **admin node** (`21001`)
- Displays its own ephemeral ECDSA public key.

Check known rooms:

```
> /rooms
✨ Known chatrooms:
  Chaincraft (admin: -----BEGIN PUB..., 0 members, 1 msgs)
```

Then **join** the room:

```
> /join Chaincraft
✅ Requested to join chatroom 'Chaincraft'.
```

---

## 3. Auto-Accepted

On the **admin node**’s console, you’ll see:

```
💬 [Chaincraft] -----BEGIN PUBLIC KE... requested to join!
✅ [Chaincraft]: User -----BEGIN PUBLIC KE... has been accepted by admin!
```

No manual `/accept` step required – the admin node is configured to auto-accept new join requests.

---

## 4. Send Messages

Now the second node can freely chat:

```
> hello from 2nd user
```

On **both** terminals, you should see:

```
💬 [Chaincraft] -----BEGIN PUB...: hello from 2nd user
```

---

## 5. Sharing More Consoles

Feel free to start a **third** node on a different port:

```bash
python -m examples.chatroom_cli --port 21003 --peer 127.0.0.1:21001
```

That node can also `/join Chaincraft`. The admin node auto-accepts it, and then **everyone** sees each other’s messages.

---

## Commands Cheat Sheet

Inside the CLI prompt:

| Command              | Description                                                                                          |
|----------------------|------------------------------------------------------------------------------------------------------|
| `/create <name>`     | Create a new chatroom (you become admin). Auto-accepts any join requests.                           |
| `/join <name>`       | Request to join a chatroom.                                                                         |
| `/msg <text>`        | Post a message to the current chatroom (or type text without a slash).                              |
| `/rooms`             | List known chatrooms, including admin, members count, and messages count.                           |
| `/help`              | Print help.                                                                                          |
| `/quit`              | Exit the CLI.                                                                                       |

> **Tip**: If you type **any text** without `/` in front, it behaves like `/msg <text>` in the current room.

---

**Thanks** for exploring the *Chaincraft* chat with **auto-accept** join requests and ephemeral ECDSA identities!