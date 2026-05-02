# C Chat with Web Frontend

A multi-room chat system built around a directory-of-services architecture in C, with a browser-based frontend that communicates with the original C servers — unmodified — through a small WebSocket proxy. The whole thing runs over TLS 1.3 with mutual certificate verification.

## What it is

The system has three independent C programs and a web layer:

- **`directoryServer5`** — A registry that knows about every running chat room. Chat servers register with it on startup and deregister on shutdown. Clients query it for the list of available rooms.
- **`chatServer5`** — One process per chat room. Hosts a topic (e.g. "KSU Football"), accepts client connections, broadcasts messages between them, and tells the directory server it exists.
- **`chatClient5`** — The original command-line client. Lists rooms, prompts the user to pick one, then handles a TLS chat session over `select()` and stdin.
- **Web frontend (Node proxy + HTML/JS)** — A drop-in replacement for `chatClient5` that runs in the browser. The C servers don't know or care that the connection is coming from a browser instead of the CLI client.

All inter-process communication is over TLS 1.3 with certificate-based identity. A chat server proves it's authoritative for its topic by presenting a cert with that topic as the Common Name. The directory server presents itself as `"Directory Server"`. Clients verify these CNs explicitly.

## How it works

### The C side

```
                 ┌────────────────────────┐
                 │   directoryServer5     │
                 │   (port 57535, TLS)    │
                 │   keeps a list of      │
                 │   registered rooms     │
                 └───────────▲────────────┘
                             │ R/L/D commands
            ┌────────────────┼────────────────┐
            │                │                │
   ┌────────┴───────┐ ┌──────┴────────┐ ┌─────┴──────────┐
   │ chatServer5    │ │ chatServer5   │ │ chatServer5    │
   │ "KSU Football" │ │ "Puppies"     │ │ "Fortnite"     │
   │ (port 50000)   │ │ (port 50001)  │ │ (port 50002)   │
   └────────▲───────┘ └───────▲───────┘ └────────▲───────┘
            │                 │                  │
            │  TLS chat sessions, broadcasted    │
            │  to other clients in the same room │
            ▼                 ▼                  ▼
        clients (CLI or web)
```

**The directory protocol** is a single byte followed by optional data:
- `L` — list rooms. Returns one line per room: `Topic IP Port\n`.
- `R <topic> <port>` — register. Requires a client cert whose CN matches the topic.
- `D <topic>` — deregister. Same cert requirement.

**The chat server protocol** is a stream of bytes over TLS:
1. On connect, server sends `Enter in your name: `.
2. Client sends a username.
3. If the name is taken, server sends `Your nickname has been taken.\nPlease enter in a new nickname: ` and tries again.
4. Once accepted, every message the client sends gets broadcast to all other clients as `username: message`.
5. Join and leave events are broadcast as `The user, X, has joined/left the chat`.

**Certificates** are checked at every hop:
- Chat servers verify the directory server's CN before registering.
- Clients verify the directory server's CN before requesting the room list.
- Clients verify each chat server's CN matches the topic before joining.
- The directory server verifies a client cert is present (with matching CN) before honoring `R` or `D`.

### The web side

```
   Browser              Node proxy              C servers
   ┌──────┐    ws://    ┌────────────┐  TLS    ┌──────────────────┐
   │ HTML │◀──────────▶ │ server.js  │◀───────▶│ directoryServer5 │
   │  JS  │             │            │         │ chatServer5 (×N) │
   └──────┘             └────────────┘         └──────────────────┘
```

Browsers can't speak raw TLS-over-TCP, so a small Node.js proxy sits in the middle. From the C servers' perspective the proxy is just another TLS client — same handshake, same CN checks, same byte stream. From the browser's perspective the proxy is just a WebSocket server.

The proxy has two modes per WebSocket connection:

1. **Directory mode (initial).** Browser sends `{"type":"list"}` as JSON. Proxy connects to the directory server, sends `L`, parses the response, sends back `{"type":"rooms", rooms:[...]}`.

2. **Chat mode (after join).** Browser sends `{"type":"join", topic, ip, port}`. Proxy opens a TLS connection to that chat server (verifying the CN matches the topic) and from then on becomes a transparent byte-pipe in both directions. Browser text → chat server. Chat server bytes → browser.

The frontend handles the C server's quirks — the username prompt, the `username: message` broadcast format, the join/leave notifications — and renders them appropriately as system messages, prompts, or chat bubbles.

## Project layout

```
.
├── chatServer5.c          # The chat room process
├── directoryServer5.c     # The room registry
├── chatClient5.c          # Original CLI client (still works)
├── common.h               # Shared constants (MAX, etc.)
├── inet.h                 # Network config (host, port)
├── certs/                 # Generated certs and CA bundle
└── chat-web/              # Web frontend
    ├── server.js          # Node proxy: HTTP static + WS bridge
    ├── package.json
    ├── public/
    │   └── index.html     # Single-file frontend (HTML + CSS + JS)
    └── certs/
        └── ca-cert.pem    # Copy of the root CA to verify servers
```

## Setup

### Prerequisites

- A Linux or macOS machine (Windows works under WSL).
- `gcc` or `clang`.
- `openssl` development headers (`libssl-dev` on Debian/Ubuntu).
- Node.js 18+ for the web layer.
- The certificates: a CA cert plus a cert+key pair for each chat room and for the directory server. The Common Name on each cert must match the role it plays — `Directory Server` for the directory, the topic name for each chat room. Generation is out of scope for this README; any standard OpenSSL CA setup works.

### Build the C side

Compile each program against OpenSSL:

```bash
gcc -o directoryServer5 directoryServer5.c -lssl -lcrypto
gcc -o chatServer5      chatServer5.c      -lssl -lcrypto
gcc -o chatClient5      chatClient5.c      -lssl -lcrypto
```

Edit `inet.h` so the host address matches your setup. For everything-on-one-machine:

```c
#define SERV_HOST_ADDR "127.0.0.1"
#define SERV_TCP_PORT  57535
```

Recompile after any change to `inet.h`.

### Set up the web layer

```bash
cd chat-web
npm install
cp ../certs/ca-cert.pem certs/
```

The proxy needs the same CA cert your C servers were signed with — that's how it verifies their identities, exactly the way `chatClient5.c` does.

## Running

You'll want four terminals (or use a process manager — see below).

**Terminal 1 — directory server:**
```bash
./directoryServer5
```

**Terminal 2+ — chat servers, one per room:**
```bash
./chatServer5 "KSU Football" 50000
./chatServer5 "Puppies" 50001
./chatServer5 "Fortnite" 50002
```

The topic name passed on the command line must match the Common Name on the cert files the server loads. See `set_cert_paths()` in `chatServer5.c` for the topic-to-cert mapping.

**Terminal N — web proxy:**
```bash
cd chat-web
npm start
```

Open **http://localhost:8080** in a browser. Pick a room, enter a username, chat.

The original CLI client still works alongside the web frontend — they connect to the same chat servers and can chat with each other.

```bash
./chatClient5
```

## Configuration reference

**`chat-web/server.js`** reads these environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `DIRECTORY_HOST` | `127.0.0.1` | Where the directory server is listening |
| `DIRECTORY_PORT` | `57535`     | Directory server's port |
| `CA_FILE`        | `./certs/ca-cert.pem` | CA cert used to verify all servers |
| `HTTP_PORT`      | `8080`      | What port the proxy listens on |

Example:

```bash
DIRECTORY_HOST=127.0.0.1 HTTP_PORT=9000 npm start
```

## Design notes

**Why a proxy instead of WebSockets in the C server?** Bolting WebSocket framing onto the existing C code would mean either pulling in `libwebsockets` (its own SSL context manager that conflicts with the existing OpenSSL setup) or hand-rolling the WS handshake and frame parser. Either way is more invasive than a small external proxy, and it would put the browser-specific concerns into code that has nothing else to do with browsers. Keeping the proxy separate means the C servers stay focused on their actual job.

**Why isn't there a "register chat room" button in the web UI?** Registration requires a client certificate whose CN matches the room topic. That's an operator-level credential, not something a random web visitor should hold. Run `chatServer5` from a shell to register rooms; the web UI is for chat *users*, not operators.

**The directory hands out whatever IP the chat server registered from.** It uses `inet_ntoa(cli_addr.sin_addr)` — the source IP of the chat server's TCP connection to the directory. If everything's on one box and `inet.h` says `127.0.0.1`, that's what gets registered, and the proxy can dial it. If a chat server registers from a LAN IP that the proxy can't route to, joining will fail. Loopback for local development.

**The proxy is the only externally-facing component.** Your C servers never need to be reachable from outside the host. Bind them to localhost in production for an extra layer of safety (the existing code uses `INADDR_ANY` — fine if there's a host firewall, otherwise consider switching to `INADDR_LOOPBACK`).

**TLS 1.3 minimum is enforced everywhere.** No fallback to older versions. If a peer can't speak 1.3, the handshake fails — which is what you want.

## License

Educational project. Use as you like.
