"""Tests for the log watcher: parsing, log rotation, player tracking and posting.

Run: python -m unittest test_enshrouded_watch -v

Start, online, join and leave lines have the shape of the live Tartaros log (2026-10-15).
The S1_/S2_/OLD_ fixtures are copied from the live 1.0 logs of 2026-10-16.
The shutdown line comes from the exe's format strings; the live server never wrote it.
"""

import http.server
import json
import os
import tempfile
import threading
import time
import unittest

import enshrouded_watch as w

START = [
    "[I 00:00:00,020] enshrouded_server(detached HEAD) - version b466cef1 (master)\n",
    "[I 00:00:00,607] Game Version (SVN): 1024233\n",
    "[I 00:00:02,905] [game_server] Switching state from LoadEcsScene to Run after 157.71 ms\n",
]
MACHINE = "[I 00:05:00,000] [server] Machine '1': Player 'Astrid' logged in\n"
JOIN = "[I 00:05:00,002] [server] Player 'Astrid' logged in with Permissions:\n"
JOIN2 = "[I 00:06:00,000] [server] Player 'Bjorn the Bold' logged in with Permissions:\n"
LEAVE_ENTITY = "[I 00:07:00,000] [server] Remove Entity for Player 'Astrid'\n"
LEAVE = "[I 00:07:00,001] [server] Remove Player 'Astrid'\n"
SHUTDOWN = "[I 00:09:00,000] [app] Trigger gameflow shutdown, exit: Quit\n"

# Live 1.0 lines (SVN 1267041), Tartaros server 1, 2026-10-16.
S1_FAILED = [  # a session that never logged in
    "[I 01:22:38,271] [online] Session failed for peer 0(3) with error 1000\n",
    "[I 01:22:38,273] [online] Removed peer 0(3)\n",
    "[W 01:22:38,276] [session] Remove player from session. Not found in online game info. Player Handle: 0(3) \n",
    "[I 01:22:38,277] [session] Player removed. Player handle: 0(3)\n",
]
S1_JOIN = [
    "[I 01:24:37,488] [server] Machine '1': Player '0(4)' logged in\n",
    "[I 01:24:37,489] [server] Player 'Hrothgar1066' logged in with Permissions:\n",
    "[I 01:24:37,489] \t - CanAccessInventories\n",
]
S1_DROP = [  # Steam auth lost: no "Remove Player" line
    "[I 02:03:05,432] [twitch_drop] Request succeeded Player '0(4)' drops:\n",
    "[E 02:03:18,101] [online] Client '76561197994179439' not authenticated by steam (error 1)\n",
    "[I 02:03:18,101] [online] Removed peer 0(4)\n",
    "[W 02:03:18,104] [session] Remove player from session. Not found in online game info. Player Handle: 0(4) \n",
    "[I 02:03:18,104] [session] Player removed. Player handle: 0(4)\n",
    "[I 02:03:18,119] [Server] Destroying player knowledge replication state for player index 0\n",
]
S1_REJOIN = [
    "[I 02:08:09,419] [server] Machine '1': Player '0(5)' logged in\n",
    "[I 02:08:09,424] [server] Player 'Hrothgar1066' logged in with Permissions:\n",
]
S1_LOGOUT = [  # normal logout: the named line first, then the session line
    "[I 03:35:48,611] [save2] Server sent final client save for 0(5).\n",
    "[I 03:35:48,676] [server] Remove Entity for Player 'Hrothgar1066'\n",
    "[I 03:35:48,678] [server] Remove Player 'Hrothgar1066'\n",
    "[I 03:35:48,678] [Server] Destroying player knowledge replication state for player index 0\n",
    "[I 03:35:48,775] [online] Disconnecting peer 0(5)\n",
    "[I 03:35:48,775] [online] Removed peer 0(5)\n",
    "[W 03:35:48,780] [session] Remove player from session. Not found in online game info. Player Handle: 0(5) \n",
    "[I 03:35:48,780] [session] Player removed. Player handle: 0(5)\n",
]
# Live server 2, 2026-10-16.
S2_JOIN = [
    "[I 01:43:32,576] [server] Machine '1': Player '0(1)' logged in\n",
    "[I 01:43:32,577] [server] Player 'Sigrun77' logged in with Permissions:\n",
]
# deathwatch_events.log lines written by the plugin builds now installed (old format).
OLD_DEATH = ("[I 1792145503] [deathwatch] Player 'Hrothgar1066' died cause=Impact pos=3709.7,792.0,1635.7 "
             "killer=eed67af1-094e-a341-a341-607d3e316557\n")
OLD_SLEEP = "[I 1792142798] [deathwatch] Player 'Hrothgar1066' sleeps sleepers=1 players=1\n"
OLD_CHAT = "[I 1792143228] [deathwatch] Player 'theodore47' says: ouch\n"


class FakeDiscord(http.server.BaseHTTPRequestHandler):
    posts = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeDiscord.posts.append(body["content"])
        self.send_response(204)
        self.end_headers()

    def log_message(self, *a):
        pass


class WatchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = http.server.HTTPServer(("127.0.0.1", 0), FakeDiscord)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.httpd.server_port}/hook"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def setUp(self):
        FakeDiscord.posts.clear()
        self.dir = tempfile.mkdtemp()
        self.log = os.path.join(self.dir, "enshrouded_server.log")
        cfg_path = os.path.join(self.dir, "config.json")
        with open(cfg_path, "w") as f:
            json.dump({"webhook_url": self.url, "servers": [{"name": "Test", "log": self.log}]}, f)
        self.cfg = w.load_config(cfg_path)
        self.watch = w.ServerWatch(self.cfg, self.cfg["servers"][0])

    def write(self, *lines, mode="a"):
        with open(self.log, mode, encoding="utf-8") as f:
            f.writelines(lines)

    def rotate(self):
        # What the game does at start: move the old log away, begin a new file.
        os.replace(self.log, self.log + ".old")

    def test_parse(self):
        self.assertEqual(w.parse_line(JOIN), ("join", {"name": "Astrid"}))
        self.assertEqual(w.parse_line(LEAVE), ("leave", {"name": "Astrid"}))
        self.assertEqual(w.parse_line(SHUTDOWN)[0], "shutdown")
        self.assertEqual(w.parse_line(START[2])[0], "online")
        self.assertIsNone(w.parse_line(MACHINE))        # same login, counted once
        self.assertIsNone(w.parse_line(LEAVE_ENTITY))   # same logout, counted once
        self.assertIsNone(w.parse_line("[I 00:00:01,000] [server] Bad Performance 5 us\n"))
        self.assertIsNone(w.parse_line("garbage"))

    def test_session(self):
        self.write(*START, mode="w")
        self.watch.poll()
        self.write(MACHINE, JOIN, JOIN2)
        self.watch.poll()
        self.write(LEAVE_ENTITY, LEAVE, SHUTDOWN)
        self.watch.poll()
        p = FakeDiscord.posts
        self.assertEqual(len(p), 6, p)
        self.assertIn("is starting", p[0])
        self.assertIn("(SVN 1024233)", p[0])   # no manifest configured in this test
        self.assertIn("is online", p[1])
        self.assertIn("**Astrid** joined Test (1 online)", p[2])
        self.assertIn("**Bjorn the Bold** joined Test (2 online)", p[3])
        self.assertIn("**Astrid** left Test (1 online)", p[4])
        self.assertIn("shutting down", p[5])

    def test_partial_line_is_held_back(self):
        self.write(*START, mode="w")
        self.watch.poll()
        self.write(JOIN[:30])
        self.watch.poll()
        self.assertEqual(len(FakeDiscord.posts), 2)
        self.write(JOIN[30:])
        self.watch.poll()
        self.assertIn("Astrid", FakeDiscord.posts[-1])

    def test_prime_is_silent_and_keeps_state(self):
        self.write(*START, JOIN, mode="w")
        self.watch.prime()
        self.assertEqual(FakeDiscord.posts, [])
        self.write(JOIN2)
        self.watch.poll()
        self.assertEqual(FakeDiscord.posts, [":arrow_right: **Bjorn the Bold** joined Test (2 online)"])

    def test_log_goes_quiet(self):
        import time
        self.write(*START, JOIN, mode="w")
        self.watch.poll()
        self.watch.poll(now=time.time() + 60)    # one missed heartbeat or so: still up
        self.assertEqual(len(FakeDiscord.posts), 3)
        self.watch.poll(now=time.time() + 200)   # killed without a shutdown line
        self.watch.poll(now=time.time() + 400)   # said once only
        self.assertEqual(FakeDiscord.posts[3:], [":red_circle: **Test** is offline"])
        self.assertEqual(self.watch.players, set())

    def test_log_deleted_and_server_hangs(self):
        import time
        self.write(*START, JOIN, mode="w")
        self.watch.poll()
        os.remove(self.log)                       # startup command: rm ./logs/enshrouded_server.log
        t = time.time()
        self.watch.poll(now=t)                    # missing, not long yet
        self.watch.poll(now=t + 60)
        self.assertEqual(len(FakeDiscord.posts), 3)
        self.watch.poll(now=t + 200)              # still no new log: the server is not up
        self.watch.poll(now=t + 400)
        self.assertEqual(FakeDiscord.posts[3:], [":red_circle: **Test** is offline"])
        self.write(*START, mode="w")              # it starts after all (restart)
        self.watch.poll()
        self.assertIn("is starting", FakeDiscord.posts[-2])
        self.assertIn("is online", FakeDiscord.posts[-1])
        self.assertEqual(sum("offline" in p for p in FakeDiscord.posts), 1)

    def test_restart_before_quiet(self):
        self.write(*START, JOIN, mode="w")
        self.watch.poll()
        self.rotate()                            # restarted within silent_seconds
        self.write(*START, mode="w")
        self.watch.poll()
        p = FakeDiscord.posts
        self.assertIn("is offline", p[3])
        self.assertIn("is starting", p[4])

    def test_clean_shutdown_not_also_offline(self):
        import time
        self.write(*START, SHUTDOWN, mode="w")
        self.watch.poll()
        self.watch.poll(now=time.time() + 400)
        self.rotate()
        self.write(*START, mode="w")
        self.watch.poll()
        self.assertFalse(any("offline" in m for m in FakeDiscord.posts))

    def test_prime_on_stopped_server(self):
        import time
        self.write(*START, JOIN, mode="w")
        self.watch.prime(now=time.time() + 400)  # watcher started while the server is down
        self.assertFalse(self.watch.running)
        self.watch.poll(now=time.time() + 500)
        self.assertEqual(FakeDiscord.posts, [])

    def test_disabled_and_custom(self):
        self.cfg["disabled_events"] = ["join"]
        self.write(*START, JOIN, mode="w")
        self.watch.poll()
        self.assertFalse(any("joined" in m for m in FakeDiscord.posts))
        w.send_custom(self.cfg, "Restart in 10 minutes")
        self.assertEqual(FakeDiscord.posts[-1], ":loudspeaker: Restart in 10 minutes")

    def test_schedule(self):
        import datetime as dt
        self.cfg["schedule"] = [{"at": "03:55", "days": ["Thu"], "text": "Restart soon"}]
        thu = dt.datetime(2026, 10, 15, 3, 55, 10)
        fired = set()
        self.assertEqual(len(list(w.due_schedule(self.cfg, thu, fired))), 1)
        self.assertEqual(len(list(w.due_schedule(self.cfg, thu, fired))), 0)  # once per minute
        self.assertEqual(len(list(w.due_schedule(self.cfg, thu + dt.timedelta(days=1), set()))), 0)

    def test_plugin_deaths(self):
        events = os.path.join(self.dir, "deathwatch_events.log")
        with open(events, "w", encoding="utf-8") as f:
            f.write("[I 1791990000] [deathwatch] Player 'Old' died\n")  # before the watcher started
        watch = w.ServerWatch(self.cfg, dict(self.cfg["servers"][0], events_log=events))
        self.write(*START, mode="w")
        watch.prime()
        with open(events, "a", encoding="utf-8") as f:
            f.write("[I 1791990100] [deathwatch] Player 'Bjørn O'Neil' died\n")
        watch.poll()
        self.assertEqual(FakeDiscord.posts, [":skull: **Bjørn O'Neil** died on Test"])

    def test_post_ingame(self):
        outbox = os.path.join(self.dir, "chat_outbox.txt")
        self.cfg["servers"][0]["chat_outbox"] = outbox
        w.send_custom(self.cfg, "Restart in\n10 minutes", ingame=True)
        w.send_custom(self.cfg, "Only in game", discord=False, ingame=True)
        self.assertEqual(FakeDiscord.posts, [":loudspeaker: Restart in\n10 minutes"])
        with open(outbox, encoding="utf-8") as f:
            self.assertEqual(f.read(), "Restart in 10 minutes\nOnly in game\n")
        w.main(["post", "-c", os.path.join(self.dir, "config.json"), "--ingame-only", "hi"])  # no outbox there
        self.assertEqual(len(FakeDiscord.posts), 1)

    def test_post_ingame_stamped_for_new_mods(self):
        outbox = os.path.join(self.dir, "chat_outbox.txt")
        server = dict(self.cfg["servers"][0], chat_outbox=outbox)
        modlog = os.path.join(self.dir, "deathwatch.log")
        self.assertIsNone(w.mod_version(server))
        with open(modlog, "w", encoding="utf-8") as f:
            f.write("[     0.000] deathwatch 0.1.0 in Z:\\home\\container\\enshrouded_server.exe\n")
        self.assertEqual(w.mod_version(server), (0, 1, 0))
        w.send_ingame(server, "old mod")
        with open(modlog, "w", encoding="utf-8") as f:
            f.write("[     0.000] deathwatch 0.2.0 in Z:\\home\\container\\enshrouded_server.exe\n")
        before = int(time.time())
        w.send_ingame(server, "new  mod")
        with open(outbox, encoding="utf-8") as f:
            lines = f.read().splitlines()
        self.assertEqual(lines[0], "old mod")
        stamp, text = lines[1].split(" ", 1)
        self.assertEqual(text, "new mod")
        self.assertTrue(stamp.startswith("@") and before <= int(stamp[1:]) <= int(time.time()))

    def test_plugin_chat(self):
        events = os.path.join(self.dir, "deathwatch_events.log")
        watch = w.ServerWatch(self.cfg, dict(self.cfg["servers"][0], events_log=events))
        self.write(*START, mode="w")
        watch.prime()
        with open(events, "a", encoding="utf-8") as f:
            f.write("[I 1] [deathwatch] Player 'theodore47' says: testing 1 2 3 says: hi\n")
        watch.poll()
        self.assertEqual(FakeDiscord.posts, [":speech_balloon: **theodore47**: testing 1 2 3 says: hi"])

    def test_plugin_sleep(self):
        events = os.path.join(self.dir, "deathwatch_events.log")
        watch = w.ServerWatch(self.cfg, dict(self.cfg["servers"][0], events_log=events))
        self.write(*START, mode="w")
        watch.prime()
        with open(events, "a", encoding="utf-8") as f:
            f.write("[I 1] [deathwatch] Player 'Astrid' sleeps sleepers=1 players=3\n")
        watch.poll()
        self.assertEqual(FakeDiscord.posts, [
            ":crescent_moon: **Astrid** went to sleep on Test, skipping the night (1 of 3 asleep)"])

    def test_plugin_death_causes(self):
        events = os.path.join(self.dir, "deathwatch_events.log")
        guid = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
        self.cfg["killers"] = {guid: "a Scavenger Brute"}
        watch = w.ServerWatch(self.cfg, dict(self.cfg["servers"][0], events_log=events))
        self.write(*START, mode="w")
        watch.prime()
        with open(events, "a", encoding="utf-8") as f:
            f.write(f"[I 1] [deathwatch] Player 'A' died cause=Impact pos=1234.6,78.9,-345.2 killer={guid}\n")
            f.write("[I 2] [deathwatch] Player 'B' died cause=Impact pos=1.0,2.0,3.0 killer=ffffffff-0000-0000-0000-000000000000\n")
            f.write("[I 3] [deathwatch] Player 'C' died cause=FallDamage pos=10.4,20.5,-30.6\n")
            f.write("[I 4] [deathwatch] Player 'D' died cause=Fog pos=0.0,0.0,0.0 deadlyfog=1\n")
            f.write("[I 5] [deathwatch] Player 'E' died cause=Drowned pos=5.0,6.0,7.0\n")
            f.write("[I 6] [deathwatch] Player 'F' died cause=Somethingnew\n")
            # Freezing: the plugin's own cause (bodyheat_depletion hook), current line format.
            f.write("[I 7] [deathwatch] death 'G' died cause=Freezing\n")
            f.write("[I 8] [deathwatch] death 'O\\'Hara' died cause=Freezing\n")
        watch.poll()
        self.assertEqual(FakeDiscord.posts, [
            ":skull: **A** was killed by a Scavenger Brute on Test at (1235, 79, -345)",
            ":skull: **B** was killed on Test at (1, 2, 3)",
            ":skull: **C** fell to their death on Test at (10, 20, -31)",
            ":skull: **D** was consumed by the Shroud on Test at (0, 0, 0)",
            ":skull: **E** drowned on Test at (5, 6, 7)",
            ":skull: **F** died on Test",
            ":skull: **G** froze to death on Test",
            ":skull: **O'Hara** froze to death on Test",
        ])

    def test_bundled_killer_names(self):
        # killers.json comes from the 1.0.0.2 game files; eed67af1-... is the killer of a live death.
        thrall = "eed67af1-094e-a341-a341-607d3e316557"
        self.assertEqual(self.cfg["killers"].get(thrall), "a Fell Thrall")
        cfg_path = os.path.join(self.dir, "override.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump({"webhook_url": "http://x", "servers": [{"name": "T", "log": "l"}],
                       "killers": {thrall: "a Thrall with a spear"}}, f)
        self.assertEqual(w.load_config(cfg_path)["killers"][thrall], "a Thrall with a spear")
        self.assertEqual(w.load_killers(os.path.join(self.dir, "missing.json")), {})

    # --- 1.0 sessions: players who drop without "Remove Player" ---

    def test_parse_session_lines(self):
        self.assertEqual(w.parse_line(S1_JOIN[0]), ("login", {"handle": "0(4)"}))
        self.assertEqual(w.parse_line(S1_JOIN[1]), ("join", {"name": "Hrothgar1066"}))
        self.assertEqual(w.parse_line(S1_DROP[4]), ("removed", {"handle": "0(4)"}))
        self.assertIsNone(w.parse_line(S1_DROP[0]))   # twitch_drop "Player '0(4)'"
        self.assertIsNone(w.parse_line(S1_DROP[3]))   # "Remove player from session ..."
        self.assertIsNone(w.parse_line("[I 00:10:00,000] [server] Start Saving\n"))  # 0.9 only

    def test_dropped_player_leaves_once(self):
        self.write(*START, *S1_FAILED, *S1_JOIN, mode="w")
        self.watch.poll()
        self.write(*S1_DROP)
        self.watch.poll()
        self.write(*S1_REJOIN)
        self.watch.poll()
        self.write(*S1_LOGOUT)
        self.watch.poll()
        expected = [
            ":arrow_right: **Hrothgar1066** joined Test (1 online)",
            ":arrow_left: **Hrothgar1066** left Test (0 online)",    # "Player removed. ... 0(4)"
            ":arrow_right: **Hrothgar1066** joined Test (1 online)",
            ":arrow_left: **Hrothgar1066** left Test (0 online)",    # "Remove Player", not again for 0(5)
        ]
        self.assertEqual(FakeDiscord.posts[2:], expected)
        # The same lines read in one go give the same posts.
        FakeDiscord.posts.clear()
        self.rotate()
        self.write(*START, *S1_FAILED, *S1_JOIN, *S1_DROP, *S1_REJOIN, *S1_LOGOUT, mode="w")
        watch = w.ServerWatch(self.cfg, self.cfg["servers"][0])
        watch.poll()
        self.assertEqual(FakeDiscord.posts[2:], expected)

    def test_dropped_player_with_others_online(self):
        self.write(*START, *S1_JOIN, *S2_JOIN, mode="w")
        self.watch.poll()
        self.write(*S1_DROP)
        self.watch.poll()
        self.assertEqual(FakeDiscord.posts[-1], ":arrow_left: **Hrothgar1066** left Test (1 online)")
        self.assertEqual(self.watch.players, {"Sigrun77"})

    def test_logins_at_once_are_not_guessed(self):
        self.write(*START,
                   "[I 00:05:00,000] [server] Machine '1': Player '0(0)' logged in\n",
                   "[I 00:05:00,001] [server] Machine '2': Player '1(1)' logged in\n",
                   "[I 00:05:00,002] [server] Player 'Astrid' logged in with Permissions:\n",
                   "[I 00:05:00,003] [server] Player 'Bjorn the Bold' logged in with Permissions:\n",
                   "[I 00:06:00,000] [session] Player removed. Player handle: 1(1)\n", mode="w")
        self.watch.poll()
        self.assertEqual(len(FakeDiscord.posts), 4)   # starting, online, 2 joins; no guessed leave
        self.assertEqual(self.watch.players, {"Astrid", "Bjorn the Bold"})

    def test_back_in_before_old_session_removed(self):
        self.write(*START, *S1_JOIN, *S1_REJOIN,
                   "[I 02:08:10,000] [session] Player removed. Player handle: 0(4)\n", mode="w")
        self.watch.poll()
        self.assertFalse(any("left" in p for p in FakeDiscord.posts))
        self.assertEqual(self.watch.players, {"Hrothgar1066"})

    def test_prime_learns_drops(self):
        self.write(*START, *S1_JOIN, *S1_DROP, mode="w")
        self.watch.prime()
        self.assertEqual(self.watch.players, set())
        self.write(*S1_REJOIN)
        self.watch.poll()
        self.assertEqual(FakeDiscord.posts, [":arrow_right: **Hrothgar1066** joined Test (1 online)"])

    # --- plugin lines ---

    def events_watch(self):
        self.events = os.path.join(self.dir, "deathwatch_events.log")
        watch = w.ServerWatch(self.cfg, dict(self.cfg["servers"][0], events_log=self.events))
        self.write(*START, mode="w")
        watch.prime()
        return watch

    def add_events(self, *lines):
        with open(self.events, "a", encoding="utf-8") as f:
            f.writelines(lines)

    # --- character names (mod 0.3.3, character_names) ------------------------------------------

    def character_watch(self, mod_line="hooks in place: player slots, deaths, character names"):
        """A watch with an events file, whose mod log says `mod_line`, primed on a running server."""
        events = os.path.join(self.dir, "deathwatch_events.log")
        with open(os.path.join(self.dir, "deathwatch.log"), "w", encoding="utf-8") as f:
            f.write("[     0.001] deathwatch 0.3.3 in Z:\\home\\container\\enshrouded_server.exe\n")
            f.write(f"[     0.400] {mod_line}\n")
        watch = w.ServerWatch(self.cfg, dict(self.cfg["servers"][0], events_log=events))
        self.write(*START, mode="w")
        watch.prime()
        return watch, events

    def plugin(self, events, *msgs):
        with open(events, "a", encoding="utf-8") as f:
            for msg in msgs:
                f.write(f"[I {int(time.time())}] [deathwatch] {msg}\n")

    def test_character_name_on_join_and_leave(self):
        watch, events = self.character_watch()
        self.write(MACHINE, JOIN)
        watch.poll()
        self.assertEqual(FakeDiscord.posts, [])  # waiting for the character name
        self.plugin(events, r"character 'Astrid' is 'Freya O\'Hara'")
        watch.poll()
        self.write(LEAVE_ENTITY, LEAVE)
        watch.poll()
        self.assertEqual(FakeDiscord.posts, [
            ":arrow_right: **Astrid** (Freya O'Hara) joined Test (1 online)",
            ":arrow_left: **Astrid** (Freya O'Hara) left Test (0 online)",
        ])

    def test_character_name_in_the_same_poll_and_same_as_account(self):
        watch, events = self.character_watch()
        self.write(MACHINE, JOIN)
        self.plugin(events, "character 'Astrid' is 'Astrid'")  # same name: nothing added
        watch.poll()
        self.assertEqual(FakeDiscord.posts, [":arrow_right: **Astrid** joined Test (1 online)"])

    def test_character_name_before_the_join_line(self):
        watch, events = self.character_watch()
        self.plugin(events, "character 'Astrid' is 'Freya'")
        self.write(MACHINE, JOIN)
        watch.poll()
        self.assertEqual(FakeDiscord.posts, [":arrow_right: **Astrid** (Freya) joined Test (1 online)"])

    def test_join_without_character_name_posts_after_the_wait(self):
        watch, _ = self.character_watch()
        self.write(MACHINE, JOIN)
        watch.poll()
        watch.poll(now=time.time() + 5)
        self.assertEqual(FakeDiscord.posts, [])
        watch.poll(now=time.time() + self.cfg["character_wait_seconds"] + 1)
        self.assertEqual(FakeDiscord.posts, [":arrow_right: **Astrid** joined Test (1 online)"])

    def test_held_join_goes_out_before_chat_and_leave(self):
        watch, events = self.character_watch()
        self.write(MACHINE, JOIN)
        watch.poll()
        self.plugin(events, "chat 'Astrid' says: hi")
        watch.poll()
        self.write(JOIN2)
        watch.poll()
        self.write("[I 00:06:00,500] [server] Remove Player 'Bjorn the Bold'\n")
        watch.poll()
        self.assertEqual(FakeDiscord.posts, [
            ":arrow_right: **Astrid** joined Test (1 online)",
            ":speech_balloon: **Astrid**: hi",
            ":arrow_right: **Bjorn the Bold** joined Test (2 online)",
            ":arrow_left: **Bjorn the Bold** left Test (1 online)",
        ])

    def test_no_wait_without_character_names_in_the_mod(self):
        watch, _ = self.character_watch("hooks in place: player slots, deaths, sleepers")
        self.write(MACHINE, JOIN)
        watch.poll()
        self.assertEqual(FakeDiscord.posts, [":arrow_right: **Astrid** joined Test (1 online)"])

    def test_parse_plugin_lines(self):
        def p(msg):
            return w.parse_line(f"[I 1792143228] [deathwatch] {msg}\n")
        # plugin/src/lib.rs event_lines: character_line
        self.assertEqual(p("character 'theodore47' is 'Astrid'"),
                         ("character", {"name": "theodore47", "character": "Astrid"}))
        self.assertEqual(p(r"character 'x\' is \'y' is 'Bjørn O\'Neil'"),
                         ("character", {"name": "x' is 'y", "character": "Bjørn O'Neil"}))
        # What plugin/src/lib.rs writes (same strings as its event_lines test).
        self.assertEqual(p("chat 'theodore47' says: testing 1 2 3"),
                         ("chat", {"name": "theodore47", "text": "testing 1 2 3"}))
        self.assertEqual(p(r"chat 'Bjørn O\'Neil' says: oh no 'Kelda' died"),
                         ("chat", {"name": "Bjørn O'Neil", "text": "oh no 'Kelda' died"}))
        self.assertEqual(p("chat 'theodore47' says: x' died cause=Fog pos=1,2,3"),
                         ("chat", {"name": "theodore47", "text": "x' died cause=Fog pos=1,2,3"}))
        self.assertEqual(p(r"chat 'Bob\' says: hi' says: x"), ("chat", {"name": "Bob' says: hi", "text": "x"}))
        self.assertEqual(p(r"death 'a\\\' died' died cause=Fog"),
                         ("death", {"name": "a\\' died", "details": " cause=Fog"}))
        self.assertEqual(p(r"death 'x\' says: y' died"), ("death", {"name": "x' says: y", "details": ""}))
        self.assertEqual(p("death 'theodore47' died"), ("death", {"name": "theodore47", "details": ""}))
        self.assertEqual(p("sleep 'Hrothgar1066' sleeps sleepers=1 players=1"),
                         ("sleep", {"name": "Hrothgar1066", "details": " sleepers=1 players=1"}))
        self.assertEqual(p("death 'a b' died"), ("death", {"name": "a b", "details": ""}))
        self.assertEqual(p("notice: mod running in safe mode, unknown server build 0x6ad10810"),
                         ("notice", {"text": "mod running in safe mode, unknown server build 0x6ad10810"}))
        self.assertIsNone(p("death 'unterminated died"))

    def test_parse_old_plugin_lines(self):
        # Plugin builds installed before this format change (server 1 keeps one for now).
        self.assertEqual(w.parse_line(OLD_CHAT), ("chat", {"name": "theodore47", "text": "ouch"}))
        self.assertEqual(w.parse_line(OLD_DEATH), ("death", {"name": "Hrothgar1066", "details":
                         " cause=Impact pos=3709.7,792.0,1635.7 killer=eed67af1-094e-a341-a341-607d3e316557"}))
        self.assertEqual(w.parse_line(OLD_SLEEP), ("sleep", {"name": "Hrothgar1066", "details": " sleepers=1 players=1"}))
        # Old-format chat is never a death or a sleep, whatever its text ends with.
        for text in ("oh no 'Kelda' died", "x' died cause=Fog pos=1,2,3", "ok' sleeps sleepers=9 players=9"):
            self.assertEqual(w.parse_line(f"[I 1] [deathwatch] Player 'theodore47' says: {text}\n"),
                             ("chat", {"name": "theodore47", "text": text}))

    def test_chat_ending_in_died_is_posted_as_chat(self):
        watch = self.events_watch()
        self.add_events("[I 1792143228] [deathwatch] Player 'theodore47' says: x' died cause=Fog pos=1,2,3\n",
                        "[I 1792143229] [deathwatch] chat 'theodore47' says: oh no 'Kelda' died\n",
                        "[I 1792143230] [deathwatch] death 'Bjørn O\\'Neil' died cause=Fog pos=1.0,2.0,3.0\n")
        watch.poll()
        self.assertEqual(FakeDiscord.posts, [
            ":speech_balloon: **theodore47**: x' died cause=Fog pos=1,2,3",
            ":speech_balloon: **theodore47**: oh no 'Kelda' died",
            ":skull: **Bjørn O'Neil** was consumed by the Shroud on Test at (1, 2, 3)",
        ])

    def test_markdown_shown_as_typed(self):
        watch = self.events_watch()
        self.write("[I 00:05:00,002] [server] Player '*star*' logged in with Permissions:\n")
        self.add_events("[I 1] [deathwatch] chat '_x_' says: see [free loot](https://evil.example) "
                        "||spoiler|| ~~x~~ `code` <@123> **b**\u2028:skull: c\\d\n")
        watch.poll()
        self.assertEqual(sorted(FakeDiscord.posts), sorted([
            ":arrow_right: **\\*star\\*** joined Test (1 online)",
            ":speech_balloon: **\\_x\\_**: see \\[free loot\\](https://evil.example) \\|\\|spoiler\\|\\| "
            "\\~\\~x\\~\\~ \\`code\\` \\<@123\\> \\*\\*b\\*\\* :skull: c\\\\d",
        ]))
        self.assertEqual(watch.players, {"*star*"})   # state keeps the name as logged

    def test_join_posted_before_plugin_line_of_same_poll(self):
        watch = self.events_watch()
        t = 1792151000
        self.write(*S2_JOIN)
        os.utime(self.log, (t, t))                    # the join line was written at t
        self.add_events(f"[I {t}] [deathwatch] death 'Sigrun77' died\n")   # written in that second
        watch.poll(now=t + 1)
        self.assertEqual(FakeDiscord.posts, [":arrow_right: **Sigrun77** joined Test (1 online)",
                                             ":skull: **Sigrun77** died on Test"])

    def test_chat_posted_before_leave_of_same_poll(self):
        watch = self.events_watch()
        self.write(*S1_JOIN)
        watch.poll()
        FakeDiscord.posts.clear()
        t = 1792151000
        self.write(*S1_LOGOUT)
        os.utime(self.log, (t, t))
        self.add_events(f"[I {t - 2}] [deathwatch] chat 'Hrothgar1066' says: bye\n")
        watch.poll(now=t + 1)
        self.assertEqual(FakeDiscord.posts, [":speech_balloon: **Hrothgar1066**: bye",
                                             ":arrow_left: **Hrothgar1066** left Test (0 online)"])

    def test_plugin_lines_posted_while_log_missing(self):
        watch = self.events_watch()
        os.remove(self.log)
        self.add_events("[I 1] [deathwatch] chat 'theodore47' says: anyone?\n")
        watch.poll()
        self.assertEqual(FakeDiscord.posts, [":speech_balloon: **theodore47**: anyone?"])

    # --- review fixes ---

    def test_unpaired_rejoin_then_late_removal(self):
        # Jase is back in (unpaired: a second login is waiting) before his old session 0(4) is
        # removed. That removal is not a leave, and his real leave later is posted once.
        self.write(*START, *S1_JOIN,
                   "[I 02:08:09,000] [server] Machine '2': Player '2(4)' logged in\n",   # no join follows
                   *S1_REJOIN,
                   "[I 02:08:10,000] [session] Player removed. Player handle: 0(4)\n", mode="w")
        self.watch.poll()
        self.assertFalse(any("left" in p for p in FakeDiscord.posts))
        self.assertEqual(self.watch.players, {"Hrothgar1066"})
        self.write(*S1_LOGOUT)
        self.watch.poll()
        self.assertEqual([p for p in FakeDiscord.posts if "left" in p],
                         [":arrow_left: **Hrothgar1066** left Test (0 online)"])

    def test_login_without_join_does_not_block_pairing(self):
        self.write(*START,
                   "[I 00:05:00,000] [server] Machine '1': Player '1(4)' logged in\n",
                   "[E 00:05:00,001] [server] Could not spawn Player Entity\n",
                   "[I 00:05:01,000] [session] Player removed. Player handle: 1(4)\n",
                   *S1_JOIN, *S1_DROP, mode="w")
        self.watch.poll()
        self.assertEqual(FakeDiscord.posts[2:], [":arrow_right: **Hrothgar1066** joined Test (1 online)",
                                                 ":arrow_left: **Hrothgar1066** left Test (0 online)"])

    def test_removed_before_remove_player(self):
        self.write(*START, *S1_JOIN,
                   "[I 02:00:00,000] [session] Player removed. Player handle: 0(4)\n",
                   "[I 02:00:00,100] [server] Remove Player 'Hrothgar1066'\n", mode="w")
        self.watch.poll()
        self.assertEqual([p for p in FakeDiscord.posts if "left" in p],
                         [":arrow_left: **Hrothgar1066** left Test (0 online)"])

    def test_prime_with_log_missing_skips_old_plugin_lines(self):
        self.events = os.path.join(self.dir, "deathwatch_events.log")
        self.add_events(OLD_DEATH, OLD_SLEEP, OLD_CHAT)          # history from earlier runs
        watch = w.ServerWatch(self.cfg, dict(self.cfg["servers"][0], events_log=self.events))
        watch.prime()                                            # no game log: server restarting
        watch.poll()
        self.assertEqual(FakeDiscord.posts, [])
        self.add_events("[I 1792150000] [deathwatch] chat 'theodore47' says: back\n")
        watch.poll()
        self.assertEqual(FakeDiscord.posts, [":speech_balloon: **theodore47**: back"])

    def test_bad_template_does_not_stop_the_poll(self):
        self.cfg["messages"]["chat"] = ":speech_balloon: **{name}**: {text} {oops}"
        watch = self.events_watch()
        t = 1792151000
        self.write("[I 00:00:01,000] [server] Player 'Bob' logged in with Permissions:\n",
                   "[I 00:00:05,000] [server] Player 'Ann' logged in with Permissions:\n")
        os.utime(self.log, (t + 5, t + 5))
        self.add_events(f"[I {t + 2}] [deathwatch] chat 'Bob' says: hi\n")
        watch.poll(now=t + 6)
        self.assertEqual(FakeDiscord.posts, [":arrow_right: **Bob** joined Test (1 online)",
                                             ":arrow_right: **Ann** joined Test (2 online)"])
        self.assertEqual(watch.players, {"Bob", "Ann"})

    def test_plugin_line_not_understood_is_logged(self):
        logged = []
        old, w.log = w.log, logged.append
        try:
            watch = self.events_watch()
            self.add_events("[I 1] [deathwatch] frobnicate 'x'\n", "garbage\n", "\n",
                            "[I 2] [deathwatch] chat 'a' says: ok\n")
            watch.poll()
        finally:
            w.log = old
        self.assertEqual(sum("line not understood" in m for m in logged), 2, logged)
        self.assertEqual(FakeDiscord.posts, [":speech_balloon: **a**: ok"])

    def test_notice_posted(self):
        watch = self.events_watch()
        self.add_events("[I 1] [deathwatch] notice: mod running in safe mode, unknown server build 0x6ad10811\n")
        watch.poll()
        self.assertEqual(FakeDiscord.posts,
                         [":warning: **Test**: mod running in safe mode, unknown server build 0x6ad10811"])

    def test_links_in_chat_kept(self):
        self.assertEqual(w.plain("map: https://enshrouded.wiki.gg/wiki/Flame_Altar?a=1|b see ~x _y_", links=True),
                         "map: https://enshrouded.wiki.gg/wiki/Flame_Altar?a=1|b see \\~x \\_y\\_")
        self.assertEqual(w.plain("[x](https://evil.example/a_b)", links=True),
                         "\\[x\\](https://evil.example/a_b)")
        self.assertEqual(w.plain("https://a.example/[x](https://evil.example)", links=True),
                         "https://a.example/\\[x\\](https://evil.example)")
        self.assertEqual(w.plain("https://a.example\\<@1>", links=True), "https://a.example\\\\\\<@1\\>")
        self.assertEqual(w.plain("HTTPS://a_b", links=True), "HTTPS://a\\_b")   # escaped: safe whether Discord links it or not
        self.assertEqual(w.plain("https://a_b"), "https://a\\_b")                # names: always escaped
        watch = self.events_watch()
        self.add_events("[I 1] [deathwatch] chat 'a_b' says: see https://x.example/a_b|c\n")
        watch.poll()
        self.assertEqual(FakeDiscord.posts, [":speech_balloon: **a\\_b**: see https://x.example/a_b|c"])

    # --- versions and updates (Steam answers faked; no network) ---

    NEWS = [  # shaped like ISteamNews items, titles as posted
        {"date": 1782744866, "title": "Changelog for Hotfix #42 v.0.9.1.2", "tags": ["patchnotes"]},
        {"date": 1778508503, "title": "Changelog for Hotfix #41 v.0.9.1.2", "tags": ["patchnotes"]},
        {"date": 1777465139, "title": "Changelog for Patch #14 v.0.9.1.1"},
        {"date": 1791988422, "title": "Release trailer, changelog... everything you need", "tags": []},
        {"date": 1790000000, "title": "1.0 Combat: changes and additions"},
    ]

    def steam_with(self, latest):
        steam = w.Steam()
        steam.latest = latest
        steam.versions = w.versions_from_news(self.NEWS)
        steam.checked = 1e18  # never refresh in tests
        return steam

    def manifest(self, build, updated=1791079200):
        path = os.path.join(self.dir, "appmanifest_2278520.acf")
        with open(path, "w") as f:
            f.write(f'"AppState"\n{{\n\t"buildid"\t\t"{build}"\n\t"LastUpdated"\t\t"{updated}"\n}}\n')
        return path

    def watch_with(self, steam, state_path=None):
        server = dict(self.cfg["servers"][0], manifest=self.manifest("23178631"))
        return w.ServerWatch(self.cfg, server, steam, w.State(state_path))

    def test_versions_from_news(self):
        self.assertEqual([v for _, v in w.versions_from_news(self.NEWS)], ["0.9.1.2", "0.9.1.2", "0.9.1.1"])
        later = w.versions_from_news([{"date": 1792000000, "title": "Enshrouded 1.0 Changelog", "tags": []}])
        self.assertEqual(later, [(1792000000, "1.0")])

    def test_label(self):
        steam = self.steam_with(("23178631", 1778508351))
        self.assertEqual(steam.label("23178631"), "v0.9.1.2")             # Steam release time
        self.assertEqual(steam.label("20000000", 1777500000), "v0.9.1.1")  # older build, install time
        steam.latest = ("25000000", 1792000000)                           # new build, no notes yet
        self.assertEqual(steam.label("25000000"), "build 25000000")

    def test_starting_says_version_then_updated(self):
        state = os.path.join(self.dir, "state.json")
        watch = self.watch_with(self.steam_with(("23178631", 1778508351)), state)
        self.write(*START, mode="w")
        watch.poll()
        self.assertEqual(FakeDiscord.posts[0], ":yellow_circle: **Test** is starting (v0.9.1.2)")
        # Next run reports another SVN: announced as an update.
        self.rotate()
        self.write(START[0], "[I 00:00:00,607] Game Version (SVN): 1100000\n", mode="w")
        watch.poll()
        self.assertIn(":sparkles: **Test** updated to", FakeDiscord.posts[-1])

    def test_update_available_once(self):
        state = os.path.join(self.dir, "state.json")
        steam = self.steam_with(("23178631", 1778508351))
        watch = self.watch_with(steam, state)
        watch.check_update()
        self.assertEqual(FakeDiscord.posts, [])                            # up to date
        steam.latest = ("25000000", 1792000000)
        steam.versions = w.versions_from_news(self.NEWS + [
            {"date": 1792000500, "title": "Enshrouded 1.0 Changelog", "tags": ["patchnotes"]}])
        watch.check_update()
        watch.check_update()
        self.assertEqual(FakeDiscord.posts, [
            ":arrow_up: Enshrouded update v1.0 is available (installed: v0.9.1.2). "
            "**Test** gets it on its next restart."])
        # A watcher restarted with the same state file does not repeat it.
        self.watch_with(steam, state).check_update()
        self.assertEqual(len(FakeDiscord.posts), 1)


if __name__ == "__main__":
    unittest.main()
