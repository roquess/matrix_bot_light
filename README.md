# Matrix Bot Light

A lightweight, modern Erlang library for building Matrix bots with end-to-end encryption (E2E) support.

Connects to any Matrix homeserver, handles encrypted rooms via Megolm/Olm, and lets you plug in your own command handler.

[![Hex.pm](https://img.shields.io/hexpm/v/matrix_bot_light.svg)](https://hex.pm/packages/matrix_bot_light)
[![Hex Docs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/matrix_bot_light)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## Features

- **E2E encryption**: Full Megolm/Olm support — reads encrypted rooms transparently
- **Key backup**: Import session keys from server backup using your recovery key
- **Cross-signing**: Uploads and maintains cross-signing keys automatically
- **SAS verification**: Supports `m.sas.v1` emoji verification flow
- **Lightweight**: Minimal dependencies, no heavy frameworks
- **Flexible**: Plug in any module or fun as your command handler

---

## Dependencies

Add to your `rebar.config`:

```erlang
{matrix_bot_light, "0.1.2"}
```

Required dependencies (pulled automatically):

- `gun` — HTTP/WebSocket client
- `certifi` — CA certificates
- `keylara` — Entropy management (ALARA pool)
- `alara` — Distributed entropy
- `public_key` — comes with Erlang/OTP

---

## Environment Variables

The bot is configured entirely via environment variables. **No credentials are hardcoded.**

| Variable | Required | Description |
|---|---|---|
| `MATRIX_TOKEN` | ✅ | Matrix access token for the bot account |
| `MATRIX_HOMESERVER` | ✅ | Full URL of the homeserver, e.g. `https://matrix.example.com` |
| `MATRIX_BOT_PASSWORD` | ⚠️ | Bot account password — required only on first run to upload cross-signing keys via UIA |
| `MATRIX_BACKUP_KEY` | 💡 | Recovery key (base58 with spaces) — enables automatic import of backed-up Megolm sessions |

### Starting the shell

```bash
MATRIX_TOKEN="syt_..." \
MATRIX_HOMESERVER="https://matrix.example.com" \
MATRIX_BOT_PASSWORD="your_password" \
MATRIX_BACKUP_KEY="EsXX xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx" \
rebar3 shell
```

`MATRIX_BOT_PASSWORD` is only needed on the **first run** (or after a state reset) to authenticate the cross-signing key upload. It can be omitted once keys are uploaded.

`MATRIX_BACKUP_KEY` is optional but strongly recommended — without it, the bot cannot decrypt messages sent before it joined a session.

---

## Usage

### 1. Write a Command Handler

Create a module that exports `handle_message/4`:

```erlang
-module(my_bot_commands).
-export([handle_message/4]).

handle_message(<<"!ping">>, RoomId, _Sender, Token) ->
    matrix_bot_light_client:send_message(RoomId, <<"Pong!">>, Token);
handle_message(<<"!hello">>, RoomId, Sender, Token) ->
    Reply = <<"Hello, ", Sender/binary, "!">>,
    matrix_bot_light_client:send_message(RoomId, Reply, Token);
handle_message(_, _, _, _) ->
    ok.
```

### 2. Start the Bot

From your application supervisor or the shell:

```erlang
Token      = os:getenv("MATRIX_TOKEN"),
Homeserver = os:getenv("MATRIX_HOMESERVER"),
{ok, _} = matrix_bot_light_client:start_link(
    list_to_binary(Token),
    Homeserver,
    [{command_handler, my_bot_commands}]
).
```

### 3. Send Messages

```erlang
matrix_bot_light_client:send_message(RoomId, <<"Hello!">>, Token).
```

---

## E2E Key Management

### Importing backup keys manually

If the bot can't decrypt a message (session not yet known), you can trigger a manual backup import from the shell:

```erlang
matrix_e2e:fetch_backup_keys(<<"EsXX xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx">>).
```

### Re-uploading the device signature

Useful after a server-side key reset:

```erlang
matrix_e2e:reupload_device_sig().
```

### SAS emoji verification

To verify this device from another client (e.g. Element):

```erlang
matrix_e2e:verify_with(<<"@user:example.com">>, <<"DEVICEID">>).
```

---

## State File

The bot persists its cryptographic state (Olm account, Megolm sessions, cross-signing keys) in `matrix_e2e_state.bin` in the working directory.

- The Matrix token is **never written** to this file
- If the file is corrupt or missing, the bot creates a fresh identity automatically (old messages will not be decryptable)
- Keep this file secure — it contains private keys

---

## License

Licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.

---

**Happy hacking!**
For questions or improvements, open an issue or PR on the repository.
