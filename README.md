# enshrouded-discord

[![Support me on Ko-fi](https://img.shields.io/badge/Ko--fi-Support%20the%20mod-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/liekos47)

Posts what happens on an Enshrouded dedicated server to Discord: server starting, online, offline,
updates, players joining and leaving with the character they play ("theodore47 (Astrid) joined"),
player deaths with their cause and killer ("was killed by a Fell Thrall"), who went to sleep, and in-game
chat. Also sends messages from Discord (or a schedule) into the game chat.

Server-only: players install nothing.

| Part | What |
|---|---|
| **Server mod** (`plugin/`, `dbghelp.dll`) | Loaded by `enshrouded_server.exe`. Player deaths (cause, position), character names, sleep messages, one sleeper skips the night, in-game chat broadcast, chat to Discord, optional chest notice and drop-factor tweaks |
| **Log watcher** (`watcher/`) | Python, runs in Docker. Follows the server log and the mod's events file, posts to a Discord webhook. Never touches the game process |

The watcher works alone too (start, online, offline, join, leave, updates); deaths, sleep, chat and
character names need the mod.

**Supported game builds:** Enshrouded 1.0 (SVN 1267041), 1.0.0.2 (SVN 1269579) and 1.0.0.3 (SVN 1273043).
On any other build the mod runs in safe mode (see [Build gate](#build-gate)).

## Install

### 1. Server mod

1. Stop the server.
2. Copy `dbghelp.dll` next to `enshrouded_server.exe`.
3. **Linux / Proton / Wine only:** Wine uses its own dbghelp unless told otherwise. With the server
   stopped, run
   `python3 tools/wine_dbghelp_override.py <server>/.steam/steam/steamapps/compatdata/2278520/pfx/user.reg`
   (adds `"dbghelp"="native,builtin"`; `--remove` undoes it).
4. Start the server. `logs/deathwatch.log` must show `hooks in place: ...` and no `WARNING` or
   `NOT installed` line. A `servermods.ini` with every setting is created on the first start.

Remove: delete `dbghelp.dll` (and run the override tool with `--remove`), restart.

### 2. Watcher

1. Create a Discord webhook (channel settings, Integrations, Webhooks).
2. Copy `watcher/` to the server host. Copy `config.example.json` to `config/config.json`, set
   `webhook_url` and the server paths.
3. Edit the volume paths in `docker-compose.yml`, then `docker compose up -d --build`.

Without Docker: `python enshrouded_watch.py run -c config.json` (Python 3, no dependencies).

## Mod settings: `servermods.ini`

Next to `enshrouded_server.exe`, read once at server start. `key = value`; `;` starts a comment.

| Key | Default | What it does |
|---|---|---|
| `death_messages` | true | player deaths (cause, position) to Discord |
| `freezing_cause` | true | freezing deaths get their own cause |
| `one_sleeper_skips_night` | true | one sleeping player skips the night |
| `sleep_messages` | true | who went to sleep, to Discord |
| `chat_to_discord` | true | player chat to Discord |
| `chat_broadcast` | false | lines from `servermods/chat_outbox.txt` go to every player's chat (the watcher's `post --ingame` and `schedule` use it) |
| `chat_type` | 4 | 4: shown like the game's join/leave notices; 0: shown as chat |
| `chest_notice` | false | a player who opens a world chest with fresh loot gets a private line in chat (see [Chest notice](#chest-notice)); needs `chat_broadcast` |
| `chest_notice_text` | `This chest refills about 30 minutes after everyone has left the area.` | the notice text (one line); set your own, see [Chest notice](#chest-notice) |
| `chest_notice_type` | 4 | like `chat_type`; any other value than 4 or 0 turns the chest notice off |
| `chest_notice_minutes` | 10 | at most one chest notice per player in this many minutes |
| `consumable_drops` | false | changes gameplay: consumables follow the resource drop factor |
| `harvest_drops` | false | changes gameplay: plant and bush harvests follow the resource drop factor |
| `character_names` | true | each player's character name to Discord, next to their account name (reads memory only) |
| `allow_unknown_build` | false | run every feature on a game build the mod was not checked against |

### Build gate

The mod knows the game builds it was checked against. On any other build (a new game update), the
features that read game structures or call game functions turn off until the mod is updated: chat
broadcast, chat to Discord, harvest drops, chest notice, death causes, character names. Deaths then post without a
cause, and Discord gets ":warning: mod running in safe mode". `allow_unknown_build = true` overrides it.

## In-game chat lines

Since game hotfix 1.0.0.2 the client shows a server chat line only when it carries the account of a
player it knows. The mod sends every line (broadcasts and chest notices) to each player separately with
that player's own account, so the lines show for everyone. Type 4 (the default) shows the text alone,
like a join or leave notice; type 0 shows it as chat with the receiving player's name in front.

## Chest notice

With `chest_notice = true`, a player who opens a chest placed in the world and gets fresh loot from it
receives `[Server] <chest_notice_text>` in chat, alone, at most once per `chest_notice_minutes`. Loot
from enemies and other containers spawned at run time does not trigger it. It changes nothing in the
game.

About the default text: the server does reset an area 30 minutes after the last player has left it
(that is where the 30 minutes come from). In testing (1.0.0.2), though, a looted chest still had not
refilled after about 6 hours with nobody online. So the default text is probably wrong for chests; set
`chest_notice_text` to whatever fits your server.

## Killer names

A death by a blow names what dealt it: ":skull: **Astrid** was killed by a Scavenger Crossbowman". The
mod reports the killer's template guid; `watcher/killers.json` maps 1453 of them (enemies, their
projectiles and explosions, traps) to a name. It is built from the server's game files by
`plugin/tools/make_killers.py` (Python 3.14+), which reads each template's internal name
(`Enemy_Fogger_Depleted_Spear`) and turns it into a readable one ("a Fell Thrall"). The dedicated server
has no English game text, so the names are a reading of the internal ones and may differ from the game's
wording. `"killers": {"<guid>": "a name"}` in the watcher config adds or overrides any of them; a killer
that is not known posts as before ("was killed") and its guid is logged.

After a game update that adds enemies:

```
python plugin/tools/make_killers.py <server folder> watcher/killers.json
```

## Character names

The game log only names a player's account. The server keeps the character name too (its ban list uses
it); the mod reads it from memory once per session, the way the server's own ban code looks it up, and
writes `character '<account>' is '<character>'` to the events file. It hooks nothing and calls no game
code, and every piece of game code it relies on is matched byte for byte at start: if a game update
changes one, the feature turns itself off and joins post as before.

The watcher holds a join post up to `character_wait_seconds` (20) for that line, only on a server whose
mod lists "character names" in `hooks in place`. A chat, death or sleep of that player, or their leave,
posts the join first. `{character}` in the join and leave templates is " (<name>)", or empty when the
character has the account's name.

## Watcher config

`webhook_url` at top level or per server; per server also `log`, `manifest`, `events_log` and
`chat_outbox`. `messages` overrides any message template (`{server}`, `{name}`, `{count}`,
`{version}`, `{text}`; joins and leaves also `{character}`; deaths also `{at}` and `{killer}`). `disabled_events` mutes events (`starting`,
`updated`, `update`, `online`, `join`, `leave`, `offline`, `death`, `sleep`, `chat`, `notice`,
`custom`). `schedule` entries: `{"at": "HH:MM", "days": ["Mon", ...], "text": ..., "server":
optional, "ingame" / "ingame_only": optional}`, host local time.

```
python enshrouded_watch.py run   -c config.json             # the service
python enshrouded_watch.py post  -c config.json "text"      # custom message (-s NAME: one server;
                                                            #   --ingame / --ingame-only: game chat)
python enshrouded_watch.py test  <logfile>                  # dry run: list events, post nothing
```

## Build from source

```
cd plugin
cargo build --release          # target/release/dbghelp.dll (Windows, x64)
cargo test --release           # SKIP_REFERENCE_EXE=1 skips tests that need the server exes
python tools/check_signatures.py <enshrouded_server.exe>   # does this build fit the mod?
```

```
cd watcher
python -m unittest test_enshrouded_watch -v
```

## Support

If this mod is useful on your server, you can support it on [Ko-fi](https://ko-fi.com/liekos47).
