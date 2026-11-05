"""Tests for the datz terminal console (no network, no TTY required)."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

import datz


def build_app(**overrides) -> datz.App:
    app = datz.App(Path("webwarden.pyz"), "0.8.4")
    app.target = "example.com"
    app.authorized = True
    for key, value in overrides.items():
        setattr(app, key, value)
    return app


class EventParsingTests(unittest.TestCase):
    def test_arrows_and_tilde_keys(self):
        events = datz.parse_events("\x1b[A\x1b[B\x1b[5~\x1b[6~\x1b[15~")
        self.assertEqual([e[1] for e in events],
                         ["up", "down", "pgup", "pgdn", "f5"])

    def test_mouse_sgr(self):
        events = datz.parse_events("\x1b[<0;12;7M\x1b[<0;12;7m")
        self.assertEqual(events[0], ("mouse", 11, 6, 0, "press"))
        self.assertEqual(events[1], ("mouse", 11, 6, 0, "release"))

    def test_plain_text_and_control(self):
        events = datz.parse_events("q\x1b[Z\r")
        self.assertEqual([e[1] for e in events], ["q", "btab", "enter"])

    def test_f1_to_f4_from_ss3(self):
        events = datz.parse_events("\x1bOP\x1bOQ")
        self.assertEqual([e[1] for e in events], ["f1", "f2"])


class OptionValidationTests(unittest.TestCase):
    def test_requires_authorization(self):
        with self.assertRaises(ValueError):
            datz.options_from_payload({"target": "example.com"})

    def test_rejects_ip_and_url(self):
        for target in ("192.0.2.10", "http://example.com/x", "example"):
            with self.assertRaises(ValueError):
                datz.options_from_payload({"target": target, "authorize": True})

    def test_scopes_accept_string_and_list(self):
        one = datz.options_from_payload(
            {"target": "example.com", "authorize": True,
             "scopes": "*.example.com, api.example.net"})
        two = datz.options_from_payload(
            {"target": "example.com", "authorize": True,
             "scopes": ["*.example.com", "api.example.net"]})
        self.assertEqual(one.scopes, ["*.example.com", "api.example.net"])
        self.assertEqual(two.scopes, one.scopes)

    def test_clamps_numbers(self):
        opts = datz.options_from_payload(
            {"target": "example.com", "authorize": True,
             "threads": "99", "timeout": "1", "rate": "500"})
        self.assertEqual(opts.threads, 12)
        self.assertEqual(opts.timeout, 2.0)
        self.assertEqual(opts.rate, 50.0)


class ArgvTests(unittest.TestCase):
    def opts(self, **kwargs) -> datz.ScanOptions:
        base = dict(target="example.com", authorized=True)
        base.update(kwargs)
        return datz.ScanOptions(**base)

    def test_full_modules_add_flags(self):
        argv = datz.build_scan_argv(
            Path("engine.pyz"),
            self.opts(bypass=True, robots=True, nuclei=True), Path("out"))
        for flag in ("--bypass", "--robots-paths", "--nuclei", "--i-am-authorized"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[3], "example.com")
        self.assertEqual(argv[argv.index("--out") + 1], "out")

    def test_disabled_modules_add_no_flags(self):
        argv = datz.build_scan_argv(
            Path("engine.pyz"),
            self.opts(injection=False, backdoors=False, secrets=False,
                      bundles=False, takeover=False, nvd=False), Path("out"))
        for flag in ("--no-injection", "--no-backdoors", "--no-secrets",
                     "--no-bundles", "--no-takeover", "--no-nvd"):
            self.assertIn(flag, argv)

    def test_shell_join_quotes_globs(self):
        joined = datz.shell_join(["datz", "--scope", "*.example.com"])
        self.assertEqual(joined, "datz --scope '*.example.com'")


class LayoutTests(unittest.TestCase):
    def test_frames_fit_inside_width(self):
        for width, height in ((72, 20), (80, 24), (110, 32), (150, 40)):
            app = build_app()
            screen = datz.draw(app, width, height)
            for line in screen.to_text().splitlines():
                self.assertLessEqual(len(line), width, f"{width}x{height}")

    def test_tab_bar_stays_inside_panel(self):
        app = build_app()
        datz.seed_demo(app, "summary")
        for width in (80, 96, 110, 128, 150, 200):
            screen = datz.draw(app, width, 34)
            left = 46 if width >= 118 else 40 if width >= 98 else 34
            lines = screen.to_text().splitlines()
            self.assertEqual(lines[1][left], "╭", width)
            self.assertEqual(lines[2][-1], "│", width)
            if width >= 110:
                self.assertIn("Files", lines[2])

    def test_small_terminal_shows_hint(self):
        screen = datz.draw(build_app(), 60, 16)
        self.assertIn("terlalu kecil", screen.to_text())

    def test_all_tabs_render(self):
        app = build_app()
        datz.seed_demo(app, "summary")
        for key, _label in datz.TABS:
            app.tab = key
            text = datz.draw(app, 110, 32).to_text()
            self.assertIn("DATZ", text)
            self.assertNotIn("Traceback", text)

    def test_overlay_and_advanced_render_border(self):
        app = build_app()
        datz.seed_demo(app, "findings")
        for overlay in (app.finding_detail(0),
                        ("help", "Bantuan", datz.HELP_TEXT),
                        ("command", "Command", app.command())):
            app.overlay = overlay
            screen = datz.draw(app, 120, 34)
            lines = screen.to_text().splitlines()
            self.assertTrue(any("╰" in line and "╯" in line for line in lines))
        app.overlay = None
        app.advanced_open = True
        self.assertIn("PENGATURAN LANJUTAN", datz.draw(app, 120, 34).to_text())


class AppStateTests(unittest.TestCase):
    def test_tab_keys_and_cycle(self):
        app = build_app()
        app.handle_key("3")
        self.assertEqual(app.tab, "findings")
        app.handle_key("f9")
        self.assertEqual(app.tab, "chains")

    def test_preset_applies_modules(self):
        app = build_app()
        app.apply_preset("full")
        self.assertTrue(app.modules["bypass"] and app.modules["robots"])
        self.assertFalse(app.modules["nuclei"])
        app.apply_preset("recon")
        self.assertTrue(app.recon_only)
        self.assertFalse(app.modules["injection"])

    def test_auth_toggle_via_space(self):
        app = build_app(authorized=False)
        app.focus = "auth"
        app.handle_key("space")
        self.assertTrue(app.authorized)

    def test_findings_navigation_clamped(self):
        app = build_app()
        datz.seed_demo(app, "findings")
        app.handle_key("home")
        self.assertEqual(app.find_sel, 0)
        app.handle_key("end")
        self.assertEqual(app.find_sel, len(app._findings()) - 1)
        for _ in range(10):
            app.handle_key("down")
        self.assertEqual(app.find_sel, len(app._findings()) - 1)

    def test_start_requires_target_and_auth(self):
        app = build_app(target="", authorized=False)
        app.start()
        self.assertFalse(app.running)
        self.assertIn("target", app.message[0])
        app.target = "example.com"
        app.start()
        self.assertFalse(app.running)
        self.assertIn("izin", app.message[0])

    def test_demo_mode_never_starts_a_scan(self):
        app = build_app()
        datz.seed_demo(app, "summary")
        self.assertTrue(app.demo)
        app.start()
        self.assertFalse(app.running)
        self.assertIsNone(app.run.proc)
        self.assertIn("demo", app.message[0])

    def test_quit_key(self):
        app = build_app()
        app.handle_key("q")
        self.assertTrue(app.quit)

    def test_advanced_edit_writes_back(self):
        app = build_app()
        app.advanced_open = True
        app.adv_index = 1
        app.handle_key("enter")
        self.assertIsNotNone(app.editing)
        for _ in range(len(app.threads)):
            app.handle_key("backspace")
        for key in ("9", "9"):
            app.handle_key(key)
        app.handle_key("enter")
        self.assertEqual(app.threads, "99")
        self.assertIsNone(app.editing)

    def test_command_preview_is_read_only_engine_call(self):
        app = build_app()
        command = app.command()
        self.assertIn("scan example.com", command)
        self.assertIn("--i-am-authorized", command)


class EnginePayloadTests(unittest.TestCase):
    """Only meaningful after `make datz` embedded the engine zipapp."""

    @unittest.skipUnless(datz.PAYLOAD_B64, "datz.py is the un-built template")
    def test_payload_is_embedded(self):
        self.assertRegex(datz.embedded_sha256(), r"^[0-9a-f]{64}$")
        self.assertGreater(len(datz.PAYLOAD_B64), 1000)

    @unittest.skipUnless(datz.PAYLOAD_B64, "datz.py is the un-built template")
    def test_ensure_engine_extracts_and_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(datz, "RUNTIME_DIR", Path(tmp)), \
                    mock.patch.object(datz, "ENGINE_PATH", Path(tmp) / "webwarden.pyz"):
                path = datz.ensure_engine()
                self.assertTrue(path.is_file())
                self.assertEqual(datz.embedded_sha256(),
                                 datz.hashlib.sha256(path.read_bytes()).hexdigest())


class SnapshotTests(unittest.TestCase):
    def snapshot(self, *argv) -> str:
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.object(sys, "argv", ["datz", *argv]):
            code = datz.main(list(argv))
        self.assertEqual(code, 0)
        return out.getvalue()

    def test_demo_snapshot_contains_findings(self):
        text = self.snapshot("--snapshot", "--demo", "--tab", "findings",
                             "--width", "110", "--height", "32")
        self.assertIn("DATZ", text)
        self.assertIn("SSTI", text)

    def test_snapshot_without_demo_is_empty_state(self):
        text = self.snapshot("--snapshot", "--width", "110", "--height", "32")
        self.assertIn("DATZ", text)
        self.assertIn("Console", text)


class HelpAndGuardTests(unittest.TestCase):
    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                code = datz.main(list(argv))
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue() + err.getvalue()

    def test_help_aliases(self):
        code, text = self.run_main("help")
        self.assertEqual(code, 0)
        self.assertIn("usage: datz", text)

    @unittest.skipUnless(datz.PAYLOAD_B64, "datz.py is the un-built template")
    def test_help_scan_passthrough(self):
        root = Path(__file__).resolve().parent.parent
        proc = subprocess.run([sys.executable, str(root / "datz.py"),
                               "help", "scan"],
                              capture_output=True, text=True, cwd=root)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("webwarden scan", proc.stdout + proc.stderr)

    def test_demo_is_dashboard_only(self):
        code, text = self.run_main("--demo", "--headless", "--target",
                                   "example.com", "--i-am-authorized")
        self.assertEqual(code, 2)
        self.assertIn("--demo hanya untuk dashboard", text)

    def test_version(self):
        code, text = self.run_main("--version")
        self.assertEqual(code, 0)
        self.assertIn(datz.APP_VERSION, text)


class FKeyTests(unittest.TestCase):
    def test_vt220_f1_to_f4(self):
        events = datz.parse_events("\x1b[11~\x1b[12~\x1b[13~\x1b[14~")
        self.assertEqual([e[1] for e in events], ["f1", "f2", "f3", "f4"])

    def test_f5_to_f12(self):
        seq = "".join(f"\x1b[{code}~" for code in
                      (15, 17, 18, 19, 20, 21, 23, 24))
        self.assertEqual(
            [e[1] for e in datz.parse_events(seq)],
            ["f5", "f6", "f7", "f8", "f9", "f10", "f11", "f12"])

    def test_modified_f1_and_ss3_arrows(self):
        events = datz.parse_events("\x1b[1;2P\x1bOA\x1bOB\x1bOD")
        self.assertEqual([e[1] for e in events],
                         ["f1", "up", "down", "left"])

    def test_f1_opens_and_closes_help(self):
        app = build_app()
        app.handle_key("f1")
        self.assertIsNotNone(app.overlay)
        self.assertEqual(app.overlay[0], "help")
        app.handle_key("esc")
        self.assertIsNone(app.overlay)


class SplitEscapeTests(unittest.TestCase):
    def test_split_incomplete(self):
        self.assertEqual(datz.split_incomplete("q\x1b[1"), ("q", "\x1b[1"))
        self.assertEqual(datz.split_incomplete("q\x1b["), ("q", "\x1b["))
        self.assertEqual(datz.split_incomplete("q\x1b"), ("q", "\x1b"))
        self.assertEqual(datz.split_incomplete("\x1b[15~"),
                         ("\x1b[15~", ""))
        self.assertEqual(datz.split_incomplete("\x1b[<0;1;1M"),
                         ("\x1b[<0;1;1M", ""))
        self.assertEqual(datz.split_incomplete("\x1bq"), ("\x1bq", ""))

    def terminal(self) -> datz.Terminal:
        term = datz.Terminal.__new__(datz.Terminal)
        term.fd = 0
        term.buf = ""
        term.buf_at = 0.0
        term.is_windows = False
        term.vt_input = False
        term.eof = False
        term.eof_reads = 0
        term.eof_at = None
        term.read_errors = 0
        return term

    def test_partial_sequence_is_held(self):
        term = self.terminal()
        with mock.patch.object(datz.select, "select",
                               return_value=([0], [], [])), \
                mock.patch.object(datz.os, "read",
                                  side_effect=[b"\x1b[1", b"5~"]):
            self.assertEqual(term.events(), [])
            self.assertEqual(term.events(), [("key", "f5")])

    def test_lone_escape_flushes(self):
        term = self.terminal()
        term.buf = "\x1b"
        term.buf_at = time.time() - 1.0
        with mock.patch.object(datz.select, "select",
                               return_value=([], [], [])):
            self.assertEqual(term.events(), [("key", "esc")])


class TelemetryFormatTests(unittest.TestCase):
    def test_clamp_pct(self):
        self.assertEqual(datz.clamp_pct("55.5"), 55.5)
        self.assertEqual(datz.clamp_pct(-4), 0.0)
        self.assertEqual(datz.clamp_pct(140), 100.0)
        self.assertIsNone(datz.clamp_pct("n/a"))
        self.assertIsNone(datz.clamp_pct(None))
        self.assertIsNone(datz.clamp_pct(float("nan")))

    def test_pct_bar(self):
        self.assertEqual(datz.pct_bar(0, 4), "░░░░")
        self.assertEqual(datz.pct_bar(100, 4), "████")
        self.assertEqual(datz.pct_bar(50, 4), "██░░")
        self.assertEqual(datz.pct_bar(None, 3), "░░░")

    def test_sparkline(self):
        self.assertEqual(datz.sparkline([], 4), "")
        self.assertEqual(datz.sparkline([0, 50, 100], 3), "▁▅█")
        self.assertEqual(len(datz.sparkline(range(40), 10)), 10)

    def test_format_uptime(self):
        self.assertEqual(datz.format_uptime(0), "0s")
        self.assertEqual(datz.format_uptime(3661), "1h 01m")
        self.assertEqual(datz.format_uptime(90061), "1d 1h")
        self.assertEqual(datz.format_uptime(None), "n/a")

    def test_weather_icon(self):
        self.assertEqual(datz.weather_icon("Sunny"), "SUN")
        self.assertEqual(datz.weather_icon("Patchy rain possible"), "RAN")
        self.assertEqual(datz.weather_icon("Thundery outbreaks"), "STM")
        self.assertEqual(datz.weather_icon("Overcast"), "OVC")
        self.assertEqual(datz.weather_icon(""), "WX")

    def test_parse_weather_fields(self):
        data = datz.parse_weather("Kediri|Partly cloudy|+32°C|65%")
        self.assertEqual(data["loc"], "Kediri")
        self.assertEqual(data["cond"], "Partly cloudy")
        self.assertEqual(data["temp"], "+32°C")
        self.assertEqual(data["hum"], "65%")
        self.assertEqual(data["icon"], "CLD")
        self.assertIn("Partly cloudy", data["text"])

    def test_parse_weather_rejects_errors(self):
        for body in ("", "   ", "Unknown location; please try again",
                     "<html><body>error</body></html>"):
            self.assertEqual(datz.parse_weather(body), {})

    def test_parse_weather_single_line(self):
        data = datz.parse_weather("Bali: Light rain +27C")
        self.assertEqual(data["text"], "Bali: Light rain +27C")
        self.assertEqual(data["loc"], "")


class SysMonitorTests(unittest.TestCase):
    def test_default_monitor_has_no_weather_thread(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(datz, "HOME", Path(tmp)):
            monitor = datz.SysMonitor()
            self.assertIsNone(monitor._thread)
            self.assertEqual(monitor.weather_source, "off")
            self.assertIsNone(monitor.cpu)
            self.assertEqual(monitor.history, [])

    def test_sample_is_safe_when_probes_fail(self):
        monitor = datz.SysMonitor(weather=False)
        with mock.patch.object(datz.SysMonitor, "_cpu_times",
                               return_value=None), \
                mock.patch.object(datz.SysMonitor, "_ram_linux",
                                  return_value=None), \
                mock.patch.object(datz.SysMonitor, "_ram_windows",
                                  return_value=None):
            monitor.cpu = None
            monitor.ram = None
            monitor.sample(time.time(), force=True)
        self.assertIsNone(monitor.cpu)
        self.assertIsNone(monitor.ram)

    def test_weather_cache_roundtrip(self):
        payload = {"text": "CLD Rain +20°C", "loc": "Kediri",
                   "cond": "Rain", "temp": "+20°C", "hum": "80%",
                   "at": time.time()}
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(datz, "HOME", Path(tmp)):
            datz.save_weather_cache(payload)
            loaded = datz.load_weather_cache()
            self.assertEqual(loaded["loc"], "Kediri")
            monitor = datz.SysMonitor(weather=False)
            self.assertEqual(monitor.weather_loc, "Kediri")
            self.assertEqual(monitor.weather_source, "cache")

    def test_weather_cache_ignores_garbage(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(datz, "HOME", Path(tmp)):
            path = Path(tmp) / "weather.json"
            path.write_text("{not json", encoding="utf-8")
            self.assertEqual(datz.load_weather_cache(), {})
            path.write_text('{"at": 1}', encoding="utf-8")
            self.assertEqual(datz.load_weather_cache(), {})

    def test_weather_worker_applies_fetch(self):
        payload = {"text": "SUN Clear +30°C", "loc": "Kediri",
                   "cond": "Clear", "temp": "+30°C", "hum": "50%"}
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(datz, "HOME", Path(tmp)), \
                mock.patch.object(datz, "fetch_weather", return_value=payload):
            monitor = datz.SysMonitor(weather=False)
            monitor.start_weather()
            for _ in range(100):
                if monitor.weather:
                    break
                time.sleep(0.01)
            monitor.close()
            monitor._thread.join(timeout=2.0)
            self.assertFalse(monitor._thread.is_alive())
            cached = datz.load_weather_cache()
        self.assertEqual(monitor.weather_temp, "+30°C")
        self.assertEqual(monitor.weather_source, "wttr.in")
        self.assertEqual(cached.get("loc"), "Kediri")

    def test_weather_worker_survives_failure(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(datz, "HOME", Path(tmp)), \
                mock.patch.object(datz, "fetch_weather",
                                  side_effect=OSError("offline")):
            monitor = datz.SysMonitor(weather=False)
            monitor.start_weather()
            time.sleep(0.05)
            monitor.close()
        self.assertEqual(monitor.weather, "")
        self.assertEqual(monitor.weather_source, "loading")


class StatusBarTests(unittest.TestCase):
    def monitor(self) -> datz.SysMonitor:
        monitor = datz.SysMonitor(weather=False)
        monitor.cpu = 42.0
        monitor.history = [10.0, 20.0, 30.0, 42.0]
        monitor.ram = 55.0
        monitor.ram_used_gb = 8.0
        monitor.ram_total_gb = 16.0
        monitor.battery = 88.0
        monitor.plugged = True
        monitor.uptime = 3661.0
        monitor.weather = "SUN Clear +30°C"
        monitor.weather_cond = "Clear"
        monitor.weather_temp = "+30°C"
        monitor.weather_loc = "Kediri"
        monitor.weather_hum = "60%"
        monitor.weather_source = "wttr.in"
        return monitor

    def test_segments_cover_every_metric(self):
        app = datz.App(Path("engine.pyz"), "test", self.monitor())
        segments = datz.system_segments(app)
        rendered = " ".join(text for parts in segments for text, _ in parts)
        for token in ("CPU", "42%", "RAM", "55%", "BAT", "88%+",
                      "WX", "+30°C", "UP", "1h 01m"):
            self.assertIn(token, rendered)

    def test_footer_fits_and_shows_values(self):
        app = datz.App(Path("engine.pyz"), "test", self.monitor())
        app.target = "example.com"
        for width in (72, 80, 100, 124, 150):
            lines = datz.draw(app, width, 34).to_text().splitlines()
            self.assertEqual(len(lines), 34)
            for line in lines:
                self.assertLessEqual(len(line), width)
        text = datz.draw(app, 150, 34).to_text()
        self.assertIn("88%+", text)
        self.assertIn("+30°C", text)

    def test_missing_values_render_na(self):
        monitor = datz.SysMonitor(weather=False)
        monitor.cpu = monitor.ram = monitor.battery = None
        app = datz.App(Path("engine.pyz"), "test", monitor)
        app.target = "example.com"
        text = datz.draw(app, 100, 30).to_text()
        self.assertIn("CPU", text)
        self.assertIn("n/a", text)

    def test_summary_system_block(self):
        app = datz.App(Path("engine.pyz"), "test", self.monitor())
        app.target = "example.com"
        app.tab = "summary"
        text = datz.draw(app, 120, 34).to_text()
        self.assertIn("// SISTEM", text)
        self.assertIn("UPTIME", text)
        self.assertIn("CUACA", text)
        self.assertIn("Kediri", text)


class BootTests(unittest.TestCase):
    def setUp(self):
        self.app = datz.App(Path("engine.pyz"), "test",
                            datz.SysMonitor(weather=False))

    def test_frames_render_progress(self):
        total = len(datz.BOOT_STEPS)
        first = datz.boot_frame(self.app, 100, 30, 0, total).to_text()
        last = datz.boot_frame(self.app, 100, 30, total, total).to_text()
        self.assertIn("SINGLE-FILE", first)
        self.assertIn(f"0/{total}", first)
        self.assertIn(f"{total}/{total}", last)
        self.assertIn("[ ok ]", last)
        self.assertNotIn("Traceback", last)

    def test_frames_fit_tiny_terminals(self):
        for width, height in ((60, 16), (72, 20), (80, 24)):
            for step in range(len(datz.BOOT_STEPS) + 1):
                frame = datz.boot_frame(self.app, width, height, step,
                                        len(datz.BOOT_STEPS))
                for line in frame.to_text().splitlines():
                    self.assertLessEqual(len(line), width)

    def test_skips_on_any_event(self):
        class FakeTerm:
            def __init__(self):
                self.writes = []
                self.pending = [("key", "f5")]
                self.eof = False

            def size(self):
                return (120, 34)

            def write(self, text):
                self.writes.append(text)

            def events(self):
                return [self.pending.pop(0)] if self.pending else []

        term = FakeTerm()
        events = datz.boot_sequence(term, self.app)
        self.assertEqual(events, [("key", "f5")])
        self.assertGreaterEqual(len(term.writes), 1)

    def test_tiny_terminal_skips_boot(self):
        class TinyTerm:
            def __init__(self):
                self.writes = []

            def size(self):
                return (55, 14)

            def write(self, text):
                self.writes.append(text)

            def events(self):
                raise AssertionError("must not poll")

        term = TinyTerm()
        self.assertEqual(datz.boot_sequence(term, self.app), [])
        self.assertEqual(term.writes, [])

    def test_sizes_that_raise_skip_boot(self):
        class BrokenTerm:
            def size(self):
                raise OSError("no tty")

        self.assertEqual(datz.boot_sequence(BrokenTerm(), self.app), [])


class DashboardFlagTests(unittest.TestCase):
    def test_dashboard_flags_parse(self):
        args = datz.build_cli().parse_args(["--no-weather", "--no-boot"])
        self.assertTrue(args.no_weather)
        self.assertTrue(args.no_boot)
        defaults = datz.build_cli().parse_args([])
        self.assertFalse(defaults.no_weather)
        self.assertFalse(defaults.no_boot)

    def test_diagnose_flag_parses(self):
        self.assertTrue(datz.build_cli().parse_args(["--diagnose"]).diagnose)


class EofHardeningTests(unittest.TestCase):
    def terminal(self) -> datz.Terminal:
        term = datz.Terminal.__new__(datz.Terminal)
        term.fd = 0
        term.buf = ""
        term.buf_at = 0.0
        term.is_windows = False
        term.vt_input = False
        term.eof = False
        term.eof_reads = 0
        term.eof_at = None
        term.read_errors = 0
        return term

    def test_zero_byte_read_is_not_a_quit(self):
        term = self.terminal()
        with mock.patch.object(datz.select, "select",
                               return_value=([0], [], [])), \
                mock.patch.object(datz.os, "read", return_value=b""):
            for _ in range(5):
                self.assertEqual(term.events(), [])
        self.assertFalse(term.eof)
        self.assertGreater(term.eof_reads, 0)

    def test_eof_after_repeated_empty_reads(self):
        term = self.terminal()
        term.eof_at = time.time() - 1.0
        with mock.patch.object(datz.select, "select",
                               return_value=([0], [], [])), \
                mock.patch.object(datz.os, "read", return_value=b""):
            for _ in range(datz.Terminal.EOF_READS):
                term.events()
        self.assertTrue(term.eof)

    def test_read_errors_become_eof(self):
        term = self.terminal()
        with mock.patch.object(datz.select, "select",
                               return_value=([0], [], [])), \
                mock.patch.object(datz.os, "read",
                                  side_effect=OSError(5, "input/output error")):
            for _ in range(3):
                term.events()
        self.assertTrue(term.eof)
        self.assertEqual(term.read_errors, 3)

    def test_real_input_resets_counter(self):
        term = self.terminal()
        term.eof_reads = 9
        term.eof_at = time.time() - 5.0
        with mock.patch.object(datz.select, "select",
                               return_value=([0], [], [])), \
                mock.patch.object(datz.os, "read", return_value=b"j"):
            self.assertEqual(term.events(), [("key", "j")])
        self.assertEqual(term.eof_reads, 0)
        self.assertIsNone(term.eof_at)
        self.assertFalse(term.eof)


class FakeTerminal:
    def __init__(self):
        self.eof = False
        self.frames: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def size(self):
        return (100, 30)

    def write(self, text):
        self.frames.append(text)

    def events(self):
        self.eof = True
        return []


class TtyString(io.StringIO):
    def isatty(self) -> bool:
        return True


class RunTuiEofTests(unittest.TestCase):
    def run_tui(self, term, reason: str) -> tuple[int, str, str]:
        out, err = TtyString(), TtyString()
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(datz, "Terminal", return_value=term), \
                    mock.patch.object(datz, "SysMonitor") as monitor_cls, \
                    mock.patch.object(datz, "HOME", Path(tmp)), \
                    mock.patch.object(datz, "LOG_PATH", Path(tmp) / "datz.log"), \
                    mock.patch.object(sys, "stdin", TtyString()), \
                    redirect_stdout(out), redirect_stderr(err):
                code = datz.run_tui(Path("webwarden.pyz"), "0.8.4",
                                    boot=False, weather=False)
            self.assertTrue(monitor_cls.called)
            log = Path(tmp) / "datz.log"
            self.assertTrue(log.is_file())
            self.assertIn(f"reason={reason}", log.read_text(encoding="utf-8"))
        return code, out.getvalue(), err.getvalue()

    def test_eof_exits_with_visible_notice(self):
        code, out, err = self.run_tui(FakeTerminal(), "eof")
        self.assertEqual(code, 3)
        self.assertIn("EOF", err)
        self.assertIn("--diagnose", err)
        self.assertEqual(out, "")

    def test_crash_is_logged_not_silent(self):
        class CrashTerm(FakeTerminal):
            def events(self):
                raise RuntimeError("boom")

        code, _out, err = self.run_tui(CrashTerm(), "crash")
        self.assertEqual(code, 1)
        self.assertIn("error tak terduga", err)
        self.assertIn("boom", err)


class DiagnoseModeTests(unittest.TestCase):
    def test_diagnose_prints_report_and_saves_it(self):
        root = Path(__file__).resolve().parent.parent
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {"DATZ_ENGINE": str(root / "webwarden.pyz")}), \
                mock.patch.object(datz, "HOME", Path(tmp)), \
                mock.patch.object(datz, "LOG_PATH", Path(tmp) / "datz.log"), \
                redirect_stdout(out):
            code = datz.main(["--diagnose"])
            saved = Path(tmp) / "diagnose.txt"
            self.assertTrue(saved.is_file())
            self.assertIn("TERM=", saved.read_text(encoding="utf-8"))
        self.assertEqual(code, 0)
        text = out.getvalue()
        self.assertIn(f"datz {datz.APP_VERSION}", text)
        self.assertIn("stdin: fd=", text)
        self.assertIn("engine version webwarden", text)


class OutputDestinationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.data = self.root / ".datz"
        patcher = mock.patch.multiple(
            datz, HOME=self.data, RUNS_DIR=self.data / "runs",
            LOG_PATH=self.data / "datz.log")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.downloads = self.root / "Downloads"
        env = mock.patch.dict(os.environ,
                              {"DATZ_DOWNLOADS": str(self.downloads)})
        env.start()
        self.addCleanup(env.stop)

    def test_kali_root_is_default(self):
        outdir = datz.new_outdir("example.com")
        self.assertEqual(outdir.parent, datz.RUNS_DIR)
        self.assertTrue(outdir.is_dir())

    def test_downloads_root_creates_run_folder(self):
        outdir = datz.new_outdir("example.com", "downloads")
        self.assertEqual(outdir.parent, self.downloads / "datz-runs")
        self.assertTrue(outdir.is_dir())
        self.assertFalse(datz.RUNS_DIR.exists())

    def test_set_dest_persists_to_config(self):
        app = build_app()
        app.set_dest("downloads")
        self.assertEqual(app.dest, "downloads")
        self.assertEqual(datz.load_config()["output"], "downloads")
        args = mock.Mock(output=None)
        self.assertEqual(datz.dest_of(args), "downloads")
        parser = datz.build_cli()
        self.assertEqual(
            parser.parse_args(["--output", "downloads"]).output, "downloads")

    def test_set_dest_refused_while_running(self):
        app = build_app(running=True)
        app.set_dest("downloads")
        self.assertEqual(app.dest, "runs")
        self.assertTrue(app.message[1])

    def test_f4_cycles_destination(self):
        app = build_app()
        app.handle_key("f4")
        self.assertEqual(app.dest, "downloads")
        app.handle_key("f4")
        self.assertEqual(app.dest, "runs")

    def test_click_on_output_button_switches(self):
        app = build_app()
        screen = datz.draw(app, 110, 32)
        region = next(item for item in screen.regions
                      if item[0] == "out:downloads")
        datz.handle_mouse(app, region[1], region[2], 0)
        self.assertEqual(app.dest, "downloads")
        self.assertEqual(app.focus, "output")

    def test_draw_shows_both_folders(self):
        app = build_app()
        text = datz.draw(app, 110, 32).to_text()
        self.assertIn("OUT", text)
        self.assertIn("KALI ~", text)
        self.assertIn("DOWNLOAD", text)

    def test_find_run_sees_downloads_folder(self):
        dl = self.downloads / "datz-runs"
        dl.mkdir(parents=True)
        run = dl / "20261029-170000-www.example.com-beef"
        run.mkdir()
        (run / "scan.json").write_text("{}", encoding="utf-8")
        self.assertEqual(datz.find_run(), run)
        self.assertIn(run.parent, datz.run_roots())


class DisclosureTests(unittest.TestCase):
    def make_run(self, root: Path, verified: bool = True,
                 security_txt: bool = False) -> Path:
        run = root / "20261029-180000-www.example.com-cafe"
        (run / "evidence").mkdir(parents=True)
        (run / "evidence" / "ok.body").write_text("x", encoding="utf-8")
        recon = {"chains": {"enabled": True, "total": 1, "observed": 1,
                            "partial": 0, "blocked": 0, "items": [{
                                "id": "xss-session-example.com",
                                "title": "Reflected input into a cookie-less session",
                                "status": "observed", "severity": "high",
                                "summary": "reflection reproduced twice",
                                "proof": ["GET /s?q=<marker> -> marker reflected"],
                                "limitations": "execution not attempted",
                                "links": []}]}}
        if security_txt:
            recon["headers"] = {"security_txt": {"www.example.com": {
                "valid": True, "contacts": ["mailto:security@example.com"]}}}
        scan = {
            "target": "www.example.com",
            "started_at": "2026-10-29T09:00:00Z",
            "finished_at": "2026-10-29T09:05:00Z",
            "stats": {"live_hosts": 2, "requests": 40,
                      "chains_observed": 1, "chains_partial": 0,
                      "chains_blocked": 0},
            "recon": recon,
            "findings": [
                {"severity": "high", "title": "Reflected input",
                 "category": "xss", "url": "https://www.example.com/s?q=1",
                 "verified": verified, "reproductions": 2},
                {"severity": "info", "title": "Server header",
                 "category": "headers", "url": "https://www.example.com/",
                 "verified": False},
            ],
        }
        (run / "scan.json").write_text(json.dumps(scan), encoding="utf-8")
        for name in ("report.html", "report.md", "findings.json"):
            (run / name).write_text("x", encoding="utf-8")
        return run

    def test_chain_proof_appears_in_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            text = datz.run_summary(self.make_run(Path(tmp)))
        self.assertIn("chains", text)
        self.assertIn("[OBSERVED]", text)
        self.assertIn("bukti: GET /s?q=<marker> -> marker reflected", text)
        self.assertIn("batas: execution not attempted", text)
        self.assertIn("access      1 kondisi terbukti / 1 perlu verifikasi", text)
        self.assertIn("proof       GET/HEAD saja", text)

    def test_empty_chain_explains_why(self):
        scan = {"findings": [{"category": "headers"}, {"category": "xss"}],
                "recon": {"chains": {"enabled": True, "items": []}}}
        text = "\n".join(datz.chain_detail_lines(scan))
        self.assertIn("0 chain", text)
        self.assertIn("bahan scan: 1 headers, 1 xss", text)

    def test_disclosure_draft_has_boundary_and_contact(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.make_run(Path(tmp), security_txt=True)
            path = datz.write_disclosure(run)
            self.assertIsNotNone(path)
            text = path.read_text(encoding="utf-8")
        self.assertIn("Laporan kerentanan - www.example.com", text)
        self.assertIn("Kondisi yang terbukti", text)
        self.assertIn("[HIGH] Reflected input", text)
        self.assertIn("sha256", text)
        self.assertIn("Tidak ada data yang dibuat, diubah, atau dihapus.", text)
        self.assertIn("security@example.com", text)

    def test_disclosure_without_proof_says_so(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.make_run(Path(tmp), verified=False)
            text = datz.disclosure_text(run, json.loads(
                (run / "scan.json").read_text(encoding="utf-8")))
        self.assertIn("Tidak ada kondisi akses yang terbukti", text)
        self.assertIn("Perlu verifikasi manual", text)
        self.assertIn("kanal pelaporan resmi program", text)

    def test_cli_disclosure_dispatch(self):
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(out):
            run = self.make_run(Path(tmp))
            self.assertEqual(datz.main(["--disclosure", str(run)]), 0)
            self.assertTrue((run / "disclosure.md").is_file())
        self.assertIn("Batas pengujian", out.getvalue())
        self.assertIn("disimpan:", out.getvalue())


class ReportSummaryTests(unittest.TestCase):
    def make_run(self, root: Path) -> Path:
        run = root / "20261029-151241-www.example.com-f353"
        (run / "evidence").mkdir(parents=True)
        (run / "evidence" / "index.html").write_text("x", encoding="utf-8")
        (run / "scan.json").write_text(json.dumps({
            "target": "www.example.com",
            "started_at": "2026-10-29T08:12:42Z",
            "finished_at": "2026-10-29T08:19:02Z",
            "stats": {"live_hosts": 3, "requests": 120,
                      "chains_observed": 1, "chains_partial": 0,
                      "chains_blocked": 2},
            "findings": [
                {"severity": "info", "title": "Version header",
                 "url": "https://www.example.com/", "verified": False},
                {"severity": "high", "title": "SSTI signal",
                 "url": "https://www.example.com/?q=1", "verified": True},
            ],
        }), encoding="utf-8")
        (run / "audit.json").write_text(json.dumps(
            {"risk_band": "elevated", "risk_score": 42}), encoding="utf-8")
        for name in ("report.md", "report.html", "findings.json",
                     "poc.sh"):
            (run / name).write_text("x", encoding="utf-8")
        return run

    def test_summary_matches_engine_style(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.make_run(Path(tmp))
            text = datz.run_summary(run)
        self.assertIn("target      www.example.com", text)
        self.assertIn("hosts       3 live / 120 requests", text)
        self.assertIn("findings    2 (1 high, 1 info)", text)
        self.assertIn("chains      1 observed / 0 partial / 2 blocked", text)
        self.assertIn("risk        elevated (42/100)", text)
        self.assertIn(f"html        {run / 'report.html'}", text)
        self.assertIn("(1 file)", text)
        self.assertIn("top findings", text)
        self.assertIn("[HIGH    ] SSTI signal", text)
        self.assertLess(text.index("[HIGH    ]"), text.index("[INFO    ]"))
        self.assertIn("(verified)", text)
        self.assertIn("next", text)
        self.assertIn(f"open report   {run / 'report.html'}", text)
        self.assertIn(f"python3 datz.py --cli audit {run / 'scan.json'}",
                      text)

    def test_summary_of_broken_run_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(datz.run_summary(Path(tmp)), "")

    def test_find_run_prefers_newest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = self.make_run(root)
            newer = root / "20261029-160000-www.example.com-aaaa"
            newer.mkdir()
            (newer / "scan.json").write_text("{}", encoding="utf-8")
            with mock.patch.object(datz, "RUNS_DIR", root), \
                    mock.patch.dict(os.environ,
                                    {"DATZ_DOWNLOADS": str(root / "dl")}):
                os.utime(old, (1_700_000_000, 1_700_000_000))
                os.utime(newer, (1_800_000_000, 1_800_000_000))
                self.assertEqual(datz.find_run(), newer)
                self.assertIsNone(datz.find_run(str(root / "nope")))

    def test_report_run_prints_and_validates(self):
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, \
                redirect_stdout(out), redirect_stderr(err):
            run = self.make_run(Path(tmp))
            self.assertEqual(datz.report_run(str(run)), 0)
            self.assertEqual(datz.report_run(str(Path(tmp) / "missing")), 2)
        self.assertIn("target      www.example.com", out.getvalue())
        self.assertIn("run tidak ditemukan", err.getvalue())

    def test_cli_report_dispatch(self):
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(out):
            run = self.make_run(Path(tmp))
            self.assertEqual(datz.main(["--report", str(run)]), 0)
        self.assertIn("top findings", out.getvalue())


class TuiExitSummaryTests(unittest.TestCase):
    def test_summary_printed_after_quit(self):
        out, err = TtyString(), TtyString()
        with tempfile.TemporaryDirectory() as tmp:
            run = ReportSummaryTests().make_run(Path(tmp))
            app = mock.Mock()
            app.quit = True
            app.run = mock.Mock(outdir=run)
            term = FakeTerminal()
            with mock.patch.object(datz, "Terminal", return_value=term), \
                    mock.patch.object(datz, "App", return_value=app), \
                    mock.patch.object(datz, "SysMonitor"), \
                    mock.patch.object(datz, "HOME", Path(tmp)), \
                    mock.patch.object(datz, "LOG_PATH", Path(tmp) / "datz.log"), \
                    mock.patch.object(sys, "stdin", TtyString()), \
                    redirect_stdout(out), redirect_stderr(err):
                code = datz.run_tui(Path("webwarden.pyz"), "0.8.4",
                                    boot=False, weather=False)
        self.assertEqual(code, 0)
        self.assertIn("top findings", out.getvalue())
        self.assertIn("next", out.getvalue())


if __name__ == "__main__":
    unittest.main()
