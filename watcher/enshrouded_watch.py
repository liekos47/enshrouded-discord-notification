#!/usr/bin/env python3
"""Enshrouded dedicated server -> Discord announcer (option A: log watcher).

Follows each server's logs/enshrouded_server.log and posts server start/online/shutdown,
player join/leave and scheduled or ad-hoc custom messages to a Discord webhook. Also checks Steam
for a newer server build ("update available") and names versions the way the patch notes do.
It never touches the game process. Python 3.9+, standard library only.

  enshrouded_watch.py run   [-c config.json]               follow the logs (the service)
  enshrouded_watch.py post  [-c config.json] [-s NAME] [--ingame | --ingame-only] TEXT
                                                           post one custom message (Discord, and/or
                                                           in-game chat via the server mod)
  enshrouded_watch.py test  [-c config.json] LOGFILE         print the events found in a log, post nothing
"""

import argparse
import datetime as dt
import heapq
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

# --- log parsing -------------------------------------------------------------------------------
# Format strings from enshrouded_server.exe 1.0 (SVN 1267041), rva in brackets. '%k' is the
# engine's own formatter: a character name as the player typed it, or a session player handle
# such as "0(4)" (index and generation).
# Every line is "[<level> <time>] <message>": the game log has the server's uptime
# ("[I 01:24:37,489] [server] ..."), the plugin's events file unix seconds ("[I 1792130060] ...").

LINE = re.compile(r"^\[(?P<level>[A-Z]) (?P<uptime>[\d:,]+)\] (?P<msg>.*)$")

# A name the plugin wrote in single quotes with \ and ' escaped (current plugin format).
QUOTED_NAME = r"'(?P<qname>(?:[^'\\]|\\.)*)'"
UNESCAPE = re.compile(r"\\(.)")

PATTERNS = [
    # (event, regex on the message part)
    # The banner (first line of a run) resets state; the SVN line a few lines later is the one
    # announced, because it carries the build the version label is derived from.
    ("boot",     re.compile(r"^enshrouded_server.* - version (?P<commit>\S+)")),        # [12dfe08]
    ("starting", re.compile(r"^Game Version \(SVN\): (?P<svn>\d+)")),                   # [12df7f8]
    ("online",   re.compile(r"^\[game_server\] Switching state from \S+ to Run\b")),     # [1310f30]
    # Not posted: logged just before "join" with the player's session handle, so a later
    # "removed" line can be tied to the name.                                             [1310d40]
    ("login",    re.compile(r"^\[server\] Machine '\d+': Player '(?P<handle>\d+\(\d+\))' logged in$")),
    ("join",     re.compile(r"^\[server\] Player '(?P<name>.*)' logged in with Permissions:")),  # [1310830]
    # Only on a normal logout. A dropped player (Steam auth lost, crash, time-out) gets no such
    # line, only "removed".                                                                [1310938]
    ("leave",    re.compile(r"^\[server\] Remove Player '(?P<name>.*)'")),
    # Not posted as such: every way out of the session logs it, after "leave" on a normal
    # logout and alone when the player dropped (see ServerWatch._apply).                  [1323dd0]
    ("removed",  re.compile(r"^\[session\] Player removed\. Player handle: (?P<handle>\d+\(\d+\))\s*$")),
    ("shutdown", re.compile(r"^\[app\] Trigger gameflow shutdown")),                     # [12dff70]
    # 1.0 logs nothing when it saves the world ("[server] Start Saving" was 0.9 only).
    #
    # Written by the deathwatch server plugin (plugin/) to logs/deathwatch_events.log. The kind
    # comes first and the name is quoted and escaped, so no character name or chat text can make
    # one kind of line read as another:
    #   chat '<name>' says: <text>
    #   death '<name>' died cause=Impact pos=1.0,2.0,3.0 killer=<guid>   (key=value part optional)
    #   sleep '<name>' sleeps sleepers=1 players=3
    #   notice: <text>        (from the plugin itself, e.g. safe mode on an unknown server build)
    ("chat",     re.compile(r"^\[deathwatch\] chat " + QUOTED_NAME + r" says: (?P<text>.*)$")),
    ("death",    re.compile(r"^\[deathwatch\] death " + QUOTED_NAME + r" died(?P<details>(?: \w+=\S+)*)$")),
    ("sleep",    re.compile(r"^\[deathwatch\] sleep " + QUOTED_NAME + r" sleeps(?P<details>(?: \w+=\S+)*)$")),
    ("notice",   re.compile(r"^\[deathwatch\] notice:? (?P<text>.*)$")),
    # Older plugin builds (server 1 still runs one): "Player '<name>' died|sleeps|says: ...", name
    # not escaped. Chat is tried first: its text is typed by players and may end in "' died".
    ("chat",     re.compile(r"^\[deathwatch\] Player '(?P<name>.*?)' says: (?P<text>.*)$")),
    ("death",    re.compile(r"^\[deathwatch\] Player '(?P<name>.*)' died(?P<details>(?: \w+=\S+)*)$")),
    ("sleep",    re.compile(r"^\[deathwatch\] Player '(?P<name>.*)' sleeps(?P<details>(?: \w+=\S+)*)$")),
]


def parse_message(msg):
    """(event, fields) for the message part of an interesting line, else None."""
    for event, rx in PATTERNS:
        hit = rx.search(msg)
        if hit:
            fields = hit.groupdict()
            if "qname" in fields:
                fields["name"] = UNESCAPE.sub(r"\1", fields.pop("qname"))
            return event, fields
    return None


def parse_line(line):
    """Return (event, fields) for an interesting log line, else None."""
    m = LINE.match(line.rstrip("\r\n"))
    return parse_message(m.group("msg")) if m else None


def seconds(stamp):
    """Line time in seconds: '01:24:37,489' (game log uptime) -> 5077.489,
    '1792130060' (plugin unix time) -> 1792130060.0."""
    value = 0.0
    try:
        for part in stamp.replace(",", ".").split(":"):
            value = value * 60 + float(part)
    except ValueError:
        return 0.0
    return value


def read_lines(lines, unknown=None):
    """([(seconds, event, fields)] for the interesting lines, seconds of the last line or None).
    unknown(line), if given, is called for every other line that is not blank."""
    out, last = [], None
    for line in lines:
        line = line.rstrip("\r\n")
        m = LINE.match(line)
        hit = None
        if m:
            last = seconds(m.group("uptime"))
            hit = parse_message(m.group("msg"))
        if hit:
            out.append((last,) + hit)
        elif unknown and line.strip():
            unknown(line)
    return out, last


# --- Discord -------------------------------------------------------------------------------------

def post_webhook(url, content, username=None, retries=3):
    body = {"content": content[:2000], "allowed_mentions": {"parse": []}}
    if username:
        body["username"] = username
    data = json.dumps(body).encode()
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, headers={
            "Content-Type": "application/json",
            "User-Agent": "enshrouded-discord (log watcher, 1.0)",
        })
        try:
            with urllib.request.urlopen(req, timeout=10):
                return True
        except urllib.error.HTTPError as e:
            if e.code == 429:  # rate limited: Discord says how long to wait
                try:
                    wait = float(json.loads(e.read()).get("retry_after", 1))
                except Exception:
                    wait = 1.0
                time.sleep(min(wait, 30))
                continue
            log(f"webhook HTTP {e.code}: {e.read()[:200]!r}")
            return False
        except Exception as e:  # network down, DNS, timeout
            log(f"webhook error: {e}")
            time.sleep(2 * (attempt + 1))
    return False


def log(text):
    print(f"{dt.datetime.now():%Y-%m-%d %H:%M:%S} {text}", flush=True)


# Discord markdown and mention syntax: shown as typed when it comes from a player.
MARKDOWN = re.compile(r"[\\*_~`|<>\[\]]")
# In chat, a web address is left as typed so Discord still links it (it applies no markdown inside
# a link, and a "\" added to it would break it). It ends at a space or at < > [ ] \, which are
# escaped as usual: no mention, masked link or escape trick can start inside it.
LINK_OR_MARKDOWN = re.compile(r"(https?://[^\s<>\[\]\\]+)|[\\*_~`|<>\[\]]")


def plain(value, links=False):
    """Player-written text (a character name, chat) for Discord: on one line, with markdown and
    mention syntax escaped so it shows as typed. links=True keeps http(s) addresses unescaped."""
    text = " ".join(str(value).split())
    if links:
        return LINK_OR_MARKDOWN.sub(lambda m: m.group(1) or "\\" + m.group(), text)
    return MARKDOWN.sub(lambda m: "\\" + m.group(), text)


# --- config --------------------------------------------------------------------------------------

DEFAULT_MESSAGES = {
    "starting": ":yellow_circle: **{server}** is starting ({version})",
    # Instead of "starting" when the installed build differs from the previous run's.
    "updated":  ":sparkles: **{server}** updated to {version} and is starting",
    "update":   ":arrow_up: Enshrouded update {latest} is available (installed: {version}). "
                "**{server}** gets it on its next restart.",
    "online":   ":green_circle: **{server}** is online",
    "join":     ":arrow_right: **{name}** joined {server} ({count} online)",
    "leave":    ":arrow_left: **{name}** left {server} ({count} online)",
    "shutdown": ":red_circle: **{server}** is shutting down",
    # Log quiet for silent_seconds, or a new run began before that: stopped, killed or crashed.
    "offline":  ":red_circle: **{server}** is offline",
    "death":    ":skull: **{name}** died on {server}{at}",
    "chat":     ":speech_balloon: **{name}**: {text}",
    "sleep":    ":crescent_moon: **{name}** went to sleep on {server}, skipping the night ({sleepers} of {players} asleep)",
    # From the server mod itself, e.g. "mod running in safe mode, unknown server build 0x...".
    "notice":   ":warning: **{server}**: {text}",
    # One per keen::DeathCause (Drowned = Suffocated under water). {killer} is " by a <name>" when
    # the killer's guid is in killers.json or the "killers" map of the config, else empty.
    "death_Impact":     ":skull: **{name}** was killed{killer} on {server}{at}",
    "death_FallDamage": ":skull: **{name}** fell to their death on {server}{at}",
    "death_Fog":        ":skull: **{name}** was consumed by the Shroud on {server}{at}",
    "death_Drowned":    ":skull: **{name}** drowned on {server}{at}",
    "death_Suffocated": ":skull: **{name}** suffocated on {server}{at}",
    # Not a keen::DeathCause: the plugin's own cause for bodyheat_depletion kills (no position).
    "death_Freezing":   ":skull: **{name}** froze to death on {server}{at}",
    "custom":   ":loudspeaker: {text}",
}


KILLERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "killers.json")


def load_killers(path=KILLERS_FILE):
    """The bundled killer names, or {} (deaths then post without one) when the file is missing or
    unreadable."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        log(f"no killer names from {path}: {e}")
        return {}


def load_config(path):
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    cfg.setdefault("poll_seconds", 1.0)
    cfg.setdefault("username", "Enshrouded")
    cfg.setdefault("silent_seconds", 120)  # 4 missed 30 s "Session" heartbeats
    msgs = dict(DEFAULT_MESSAGES)
    msgs.update(cfg.get("messages", {}))
    cfg["messages"] = msgs
    # Events posted unless listed in "disabled_events".
    cfg.setdefault("disabled_events", [])
    cfg.setdefault("schedule", [])
    cfg.setdefault("update_check_minutes", 10)   # 0 turns the Steam check off
    cfg.setdefault("state_file", None)           # remembers announced builds and last versions
    # killer guid (from deaths) -> readable name: killers.json next to this script (from the game
    # files, plugin/tools/make_killers.py), then the config's own "killers", which win.
    cfg["killers"] = {**load_killers(), **cfg.get("killers", {})}
    for s in cfg["servers"]:
        s.setdefault("webhook_url", cfg.get("webhook_url"))
        if not s["webhook_url"]:
            sys.exit(f"server {s['name']!r}: no webhook_url (set it per server or at top level)")
    return cfg


# --- Steam: installed build, latest build, readable version ---------------------------------------

SERVER_APPID = 2278520   # Enshrouded Dedicated Server
GAME_APPID = 1203620     # Enshrouded (where the patch notes are posted)


def read_manifest(path):
    """(buildid, LastUpdated) from a steamapps/appmanifest_2278520.acf, or (None, None)."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return None, None
    build = re.search(r'"buildid"\s+"(\d+)"', text)
    updated = re.search(r'"LastUpdated"\s+"(\d+)"', text)
    return (build.group(1) if build else None), (int(updated.group(1)) if updated else None)


def get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "enshrouded-discord (log watcher)"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)


VERSION_IN_TITLE = re.compile(r"\bv\.?\s*(\d+(?:\.\d+){1,3})\b|\b(\d+\.\d+(?:\.\d+){0,2})\b")
CHANGELOG_TITLE = re.compile(r"changelog|patch ?notes|hotfix|patch #", re.I)


def versions_from_news(items):
    """[(date, "0.9.1.2"), ...] newest first, from patch-note titles."""
    out = []
    for n in items:
        if "patchnotes" not in (n.get("tags") or []) and not CHANGELOG_TITLE.search(n["title"]):
            continue
        m = VERSION_IN_TITLE.search(n["title"])
        if m:
            out.append((n["date"], m.group(1) or m.group(2)))
    return sorted(out, reverse=True)


class Steam:
    """Latest public server build (api.steamcmd.net, a mirror of Steam's app info: Steam's own
    API does not give it without a login) and the version names from Steam patch notes."""

    def __init__(self):
        self.latest = None          # (buildid, timeupdated)
        self.versions = []          # from versions_from_news
        self.checked = 0.0

    def refresh(self):
        self.checked = time.time()
        try:
            branch = get_json(f"https://api.steamcmd.net/v1/info/{SERVER_APPID}")[
                "data"][str(SERVER_APPID)]["depots"]["branches"]["public"]
            self.latest = (branch["buildid"], int(branch["timeupdated"]))
        except Exception as e:
            log(f"steam build check failed: {e}")
        try:
            news = get_json("https://api.steampowered.com/ISteamNews/GetNewsForApp/v2/"
                            f"?appid={GAME_APPID}&count=50&maxlength=1&feeds=steam_community_announcements")
            self.versions = versions_from_news(news["appnews"]["newsitems"]) or self.versions
        except Exception as e:
            log(f"steam news check failed: {e}")

    def version_at(self, when, window_days=None):
        """Newest patch-note version posted no later than two days after `when` (and, with a
        window, no earlier than that many days before it)."""
        for date, version in self.versions:
            if date <= when + 2 * 86400:
                if window_days is None or date >= when - window_days * 86400:
                    return version
                return None
        return None

    def label(self, build, install_time=None):
        """'v0.9.1.2' for a build, falling back to 'build N' when no patch note fits.

        With Steam's release time of the build, the note must be from around then, so a new
        build whose patch notes are not out yet is not called by the previous version. With
        only the install time (an older build), the newest note before the install is used.
        """
        if not build:
            return "unknown version"
        if self.latest and self.latest[0] == build:
            version = self.version_at(self.latest[1], window_days=14)
        else:
            version = self.version_at(install_time) if install_time else None
        return f"v{version}" if version else f"build {build}"


class State:
    """Small JSON file: builds already announced and each server's last SVN."""

    def __init__(self, path):
        self.path, self.data = path, {}
        if path:
            try:
                with open(path, encoding="utf-8") as f:
                    self.data = json.load(f)
            except (OSError, ValueError):
                pass

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = value
        if self.path:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=1)
            os.replace(tmp, self.path)


# --- following one server's log ------------------------------------------------------------------

class ServerWatch:
    """Follows logs/enshrouded_server.log of one server.

    A new file (different inode, or smaller than our offset) means a new server run. Under
    Proton a panel stop kills the process without writing any shutdown line (seen on Tartaros
    2026-10-15), so "offline" comes from the log going quiet: a running server writes a
    "Session" status block every 30 s.
    """

    def __init__(self, cfg, server, steam=None, state=None):
        self.cfg = cfg
        self.steam = steam or Steam()
        self.state = state or State(None)
        self.manifest = server.get("manifest")
        self.name = server["name"]
        self.path = server["log"]
        self.webhook = server["webhook_url"]
        self.silent_seconds = server.get("silent_seconds", cfg["silent_seconds"])
        self.offset = 0
        self.file_id = None
        self.partial = ""
        self.players = set()
        self.handles = {}        # session handle ("0(4)") -> name, players logged in this run
        self.logins = []         # handles from "login" lines whose "join" line has not come yet
        self.dropped = set()     # names whose leave was posted from "removed" (no "leave" line)
        self.clock = 0.0         # unix time = clock + game-log uptime (see _read_new)
        self.running = False     # from "starting" until "shutdown" or the log goes quiet
        self.missing_since = None  # when the log was first seen missing (None: present)
        self.events = EventsFile(server["events_log"]) if server.get("events_log") else None

    def _identity(self, st):
        # Not ctime: on Linux it changes on every write. A reused inode is still caught by
        # the size check in poll(), since a fresh log is smaller than the old offset.
        return (st.st_dev, st.st_ino)

    def _quiet(self, st, now):
        return now - st.st_mtime > self.silent_seconds

    def prime(self, now=None):
        """At watcher start: replay the current log silently to learn state, post nothing."""
        if self.events:
            # First, so that old plugin lines are never posted, also when the game log is missing
            # (deleted by the startup command, server updating or hung).
            self.events.skip_existing()
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            log(f"[{self.name}] primed: no game log yet")
            return
        self.file_id = self._identity(st)
        for _, event, fields in self._read_new(st):
            self._apply(event, fields)
            if event == "starting" and self.state.get(f"last_svn:{self.name}") is None:
                self.state.set(f"last_svn:{self.name}", fields["svn"])  # so the next run can say "updated"
        if self._quiet(st, now or time.time()):
            self.running = False
            self._clear_players()
        log(f"[{self.name}] primed: running={self.running} players={sorted(self.players)}")

    def poll(self, now=None):
        now = now or time.time()
        # The events file is read first: every plugin line read now was written before the game
        # log is read below, so the game-log lines from before it are in this poll too.
        # Plugin lines carry whole unix seconds: +0.5 for "somewhere in that second".
        plugin = [(t + 0.5, True, event, fields) for t, event, fields in
                  (self.events.read_new() if self.events else [])]
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            self._post(plugin)
            # The startup command deletes the log before launching the server. If no new log
            # appears within silent_seconds (an update, or a server hung before logging, seen
            # with 1.0 on 2026-10-16), the server is not up: say so once.
            if self.missing_since is None:
                self.missing_since = now
            elif self.running and now - self.missing_since > self.silent_seconds:
                self._go_offline()
            return
        except OSError as e:
            self._post(plugin)
            log(f"[{self.name}] cannot read {self.path}: {e}")
            return
        self.missing_since = None
        ident = self._identity(st)
        if ident != self.file_id or st.st_size < self.offset:
            # New server run. If the old one never went quiet in our eyes, say it is gone.
            if self.running:
                self._go_offline()
            self.file_id, self.offset, self.partial = ident, 0, ""
        try:
            lines = self._read_new(st)
        except OSError as e:  # e.g. deleted by a restart between stat and open: read it next poll
            log(f"[{self.name}] cannot read {self.path}: {e}")
            lines = []
        # Post both files' lines in the order they happened, so a join comes before a death or
        # chat right after it and a "bye" before the leave. Game-log lines: clock + uptime. On a
        # tie the game-log line goes first.
        game = [(self.clock + t, False, event, fields) for t, event, fields in lines]
        self._post(heapq.merge(game, plugin, key=lambda item: item[0]))
        if self.running and self._quiet(st, now):
            self._go_offline()

    def _post(self, items):
        """Apply and post (time, from_plugin, event, fields) items in order. A failing item (a
        template naming an unknown field, a state file that cannot be written) is logged and
        skipped, so the rest still update the player list and get posted."""
        for _, from_plugin, event, fields in items:
            try:
                if from_plugin:
                    self._post_plugin(event, fields)
                else:
                    out = self._apply(event, fields)
                    if out:
                        self._emit(*out)
            except Exception as e:
                log(f"[{self.name}] cannot post {event} {fields}: {e!r}")

    def _post_plugin(self, event, fields):
        """Post one line of the plugin's events file (only its own kinds)."""
        if event == "death":
            event, fields = death_message(self.cfg, fields)
        elif event == "sleep":
            details = dict(kv.split("=", 1) for kv in fields.pop("details", "").split())
            fields = {**fields, "sleepers": details.get("sleepers", "?"), "players": details.get("players", "?")}
        elif event not in ("chat", "notice"):
            return
        self._emit(event, fields)

    def check_update(self):
        """Post once per new Steam build that this server does not have yet."""
        if not self.manifest or not self.steam.latest:
            return
        build, label = self.installed()
        latest = self.steam.latest[0]
        if not build or int(latest) <= int(build):
            return
        key = f"announced:{self.name}"
        if self.state.get(key) == latest:
            return
        self.state.set(key, latest)
        self._emit("update", {"version": label, "latest": self.steam.label(latest)})

    def _go_offline(self):
        self._emit("offline", {})
        self.running = False
        self._clear_players()

    def _clear_players(self):
        self.players.clear()
        self.handles.clear()
        self.logins.clear()
        self.dropped.clear()

    def _read_new(self, st):
        """[(uptime seconds, event, fields)] for the complete lines added since the last read.
        Also sets self.clock from the file's mtime and its last line: the game writes each line
        as it happens (mtime matches the last uptime to about a second on Tartaros)."""
        if st.st_size <= self.offset:
            return []
        with open(self.path, "rb") as f:
            f.seek(self.offset)
            chunk = f.read()
            mtime = os.fstat(f.fileno()).st_mtime
        self.offset += len(chunk)
        text = self.partial + chunk.decode("utf-8", errors="replace")
        lines = text.split("\n")
        self.partial = lines.pop()  # incomplete last line, finish it next poll
        out, last = read_lines(lines)
        if last is not None:
            self.clock = mtime - last
        return out

    def installed(self):
        """(buildid, readable label) of what this server has installed."""
        build, updated = read_manifest(self.manifest) if self.manifest else (None, None)
        return build, self.steam.label(build, updated)

    def _apply(self, event, fields):
        """Update the state from one game-log event. Returns (event, fields) to post, or None."""
        if event == "boot":
            self.running = True
            self._clear_players()
        elif event == "login":
            self.logins.append(fields["handle"])
            return None
        elif event == "join":
            name = fields["name"]
            # A name has at most one handle: the one of its latest login. An older session of
            # this name whose "removed" line comes late must not post a leave.
            for handle in [h for h, n in self.handles.items() if n == name]:
                del self.handles[handle]
            # The login line is logged 1-5 ms before this one. With two logins waiting (two players
            # finishing together, or a login that ended without a join line: "Could not spawn
            # Player Entity", or a spawn/permission failure that logs nothing) which handle is
            # whose is not known, and none is paired.
            if len(self.logins) == 1:
                self.handles[self.logins[0]] = name
            self.logins.clear()
            self.players.add(name)
            self.dropped.discard(name)
        elif event == "leave":
            name = fields["name"]
            if name not in self.players and name in self.dropped:
                self.dropped.discard(name)
                return None  # already posted from its "removed" line
            self.players.discard(name)
            for handle in [h for h, n in self.handles.items() if n == name]:
                del self.handles[handle]
        elif event == "removed":
            # After a normal logout the "leave" line came first and forgot the handle. A dropped
            # player has no "leave" line: this is the only sign they are gone.
            handle = fields["handle"]
            if handle in self.logins:
                self.logins.remove(handle)
            name = self.handles.pop(handle, None)
            if name is None or name not in self.players:
                return None  # never logged in, an older session of a name now back in, or gone
            self.players.discard(name)
            self.dropped.add(name)
            return "leave", {"name": name}
        elif event == "shutdown":
            self.running = False
            self._clear_players()
        return event, fields

    def _emit(self, event, fields):
        if event == "starting":
            build, label = self.installed()
            fields = {**fields, "version": label if build else f"SVN {fields['svn']}"}
            key = f"last_svn:{self.name}"
            if self.state.get(key) not in (None, fields["svn"]) and "updated" not in self.cfg["disabled_events"]:
                event = "updated"
            self.state.set(key, fields["svn"])
        if event in self.cfg["disabled_events"]:
            return
        tmpl = self.cfg["messages"].get(event)
        if not tmpl:
            return
        # Names and chat are typed by players: no markdown, mentions or extra lines in Discord.
        # Web addresses in chat stay as typed so they still link.
        fields = {k: plain(v, links=k == "text") if k in ("name", "text") else v for k, v in fields.items()}
        text = tmpl.format(server=self.name, count=len(self.players), **{
            "name": "", "version": "?", "latest": "?", **fields})
        log(f"[{self.name}] {event}: {text}")
        post_webhook(self.webhook, text, self.cfg["username"])


def death_message(cfg, fields):
    """Pick the per-cause template and fill {at} and {killer} from the plugin's key=value part."""
    details = dict(kv.split("=", 1) for kv in fields.get("details", "").split())
    out = {"name": fields["name"], "at": "", "killer": ""}
    if "pos" in details:
        try:
            x, y, z = (float(v) for v in details["pos"].split(","))
            out["at"] = f" at ({x:.0f}, {y:.0f}, {z:.0f})"
        except ValueError:
            pass
    guid = details.get("killer")
    if guid:
        known = cfg["killers"].get(guid)
        if known:
            out["killer"] = f" by {known}"
        else:
            log(f"unknown killer guid {guid} (add it to \"killers\" in the config to name it)")
    event = f"death_{details['cause']}" if details.get("cause") else "death"
    return (event if event in cfg["messages"] else "death"), out


class EventsFile:
    """An append-only file of extra events (the plugin's deaths). Lines already there when the
    watcher starts are not posted again."""

    def __init__(self, path):
        self.path, self.offset, self.partial, self.ident = path, 0, "", None

    def skip_existing(self):
        try:
            st = os.stat(self.path)
            self.offset, self.ident = st.st_size, (st.st_dev, st.st_ino)
        except OSError:
            pass

    def read_new(self):
        try:
            st = os.stat(self.path)
        except OSError:
            return []
        if (st.st_dev, st.st_ino) != self.ident or st.st_size < self.offset:
            self.offset, self.partial, self.ident = 0, "", (st.st_dev, st.st_ino)
        if st.st_size <= self.offset:
            return []
        try:
            with open(self.path, "rb") as f:
                f.seek(self.offset)
                chunk = f.read()
        except OSError as e:  # retried next poll; the game log is still read
            log(f"cannot read {self.path}: {e}")
            return []
        self.offset += len(chunk)
        lines = (self.partial + chunk.decode("utf-8", errors="replace")).split("\n")
        self.partial = lines.pop()
        return read_lines(lines, self._unknown)[0]  # [(unix seconds, event, fields)]

    def _unknown(self, line):
        # Every line the plugin writes is meant to be posted: one that does not parse means the
        # plugin and the watcher disagree on the format (a newer DLL than this watcher?).
        log(f"{self.path}: line not understood, not posted: {line[:300]!r}")


# --- scheduled custom messages -------------------------------------------------------------------

DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def due_schedule(cfg, now, fired):
    """Yield schedule entries due at `now` (local time), each at most once per minute."""
    for i, entry in enumerate(cfg["schedule"]):
        if entry.get("at") != now.strftime("%H:%M"):
            continue
        days = [d.lower()[:3] for d in entry.get("days", DAYS)]
        if DAYS[now.weekday()] not in days:
            continue
        key = (i, now.strftime("%Y-%m-%d %H:%M"))
        if key in fired:
            continue
        fired.add(key)
        yield entry


def send_custom(cfg, text, server_name=None, discord=True, ingame=False):
    targets = [s for s in cfg["servers"] if server_name in (None, s["name"])]
    if not targets:
        sys.exit(f"no server named {server_name!r}")
    if discord:
        sent = set()
        for s in targets:
            if s["webhook_url"] in sent:  # servers sharing one channel get it once
                continue
            sent.add(s["webhook_url"])
            content = cfg["messages"]["custom"].format(text=text, server=s["name"])
            post_webhook(s["webhook_url"], content, cfg["username"])
    if ingame:
        for s in targets:
            send_ingame(s, text)


def mod_version(server):
    """The server mod's version from the first line of logs/deathwatch.log, next to the game log
    ("[     0.000] deathwatch 0.2.0 in ..."), or None."""
    path = os.path.join(os.path.dirname(server.get("log", "")), "deathwatch.log")
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            head = [f.readline() for _ in range(5)]
    except OSError:
        return None
    for line in head:
        m = re.search(r"\bdeathwatch (\d+)\.(\d+)\.(\d+)\b", line)
        if m:
            return tuple(int(x) for x in m.groups())
    return None


def send_ingame(server, text):
    """Append a line to the server mod's chat outbox (servermods/chat_outbox.txt next to the
    server exe, mounted into this container). The mod shows it in game as "[Server] <text>" when
    its chat_broadcast option is on; it takes the file whole, so appending is safe. Mods from
    0.2.0 on read "@<unix time> <text>" and drop a line that waited more than 5 minutes; older
    ones would show the stamp, so they get the plain line."""
    path = server.get("chat_outbox")
    if not path:
        log(f"[{server['name']}] no chat_outbox configured: not sent in game")
        return False
    line = " ".join(text.split())[:1000]  # one line, as the mod reads it
    version = mod_version(server)
    stamped = f"@{int(time.time())} {line}" if version is not None and version >= (0, 2, 0) else line
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(stamped + "\n")
    except OSError as e:
        log(f"[{server['name']}] cannot write {path}: {e}")
        return False
    log(f"[{server['name']}] in-game chat queued: {line}")
    return True


# --- commands ------------------------------------------------------------------------------------

def cmd_run(cfg):
    steam, state = Steam(), State(cfg["state_file"])
    if cfg["update_check_minutes"]:
        steam.refresh()
    watches = [ServerWatch(cfg, s, steam, state) for s in cfg["servers"]]
    for w in watches:
        w.prime()
        if w.manifest:
            log(f"[{w.name}] installed: {w.installed()}, steam latest: {steam.latest}")
    fired = set()
    log(f"watching {len(watches)} server(s)")
    while True:
        for w in watches:
            try:
                w.poll()
            except Exception as e:  # a bad read must not stop the other servers
                log(f"[{w.name}] poll error: {e}")
        if cfg["update_check_minutes"] and time.time() - steam.checked > 60 * cfg["update_check_minutes"]:
            steam.refresh()
            for w in watches:
                w.check_update()
        for entry in due_schedule(cfg, dt.datetime.now(), fired):
            send_custom(cfg, entry["text"], entry.get("server"),
                        discord=not entry.get("ingame_only"), ingame=bool(entry.get("ingame") or entry.get("ingame_only")))
        if len(fired) > 1000:
            fired.clear()
        time.sleep(cfg["poll_seconds"])


def cmd_test(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            hit = parse_line(line)
            if hit:
                print(f"{n:6}: {hit[0]:9} {hit[1]}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("run", "post"):
        p = sub.add_parser(name)
        p.add_argument("-c", "--config", default=os.environ.get("ENSHROUDED_WATCH_CONFIG", "config.json"))
    sub.choices["post"].add_argument("-s", "--server", help="only this server's webhook (default: all)")
    where = sub.choices["post"].add_mutually_exclusive_group()
    where.add_argument("--ingame", action="store_true", help="also show it in every player's in-game chat")
    where.add_argument("--ingame-only", action="store_true", help="only in-game chat, not Discord")
    sub.choices["post"].add_argument("text", nargs="+")
    sub.add_parser("test").add_argument("logfile")
    args = ap.parse_args(argv)

    if args.cmd == "test":
        return cmd_test(args.logfile)
    cfg = load_config(args.config)
    if args.cmd == "post":
        return send_custom(cfg, " ".join(args.text), args.server,
                           discord=not args.ingame_only, ingame=args.ingame or args.ingame_only)
    return cmd_run(cfg)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
