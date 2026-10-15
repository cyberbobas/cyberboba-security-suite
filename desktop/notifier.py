#!/usr/bin/env python3
"""Tiny notification helper for the cyberboba desktop shell.

Speaks newline-delimited JSON on stdin/stdout and owns ONE D-Bus connection to
org.freedesktop.Notifications. That matters: GNOME Shell delivers
ActionInvoked / NotificationClosed only to the connection that created the
notification, so creating banners with `gdbus call` and watching with
`gdbus monitor` (two connections) never sees the button clicks. Electron has
no action buttons on Linux and no D-Bus binding, hence this helper.

stdin  -> {"op":"notify","ref":"<any>","summary":"..","body":"..","actions":["key","Label",..],"icon":"/path","urgency":2,"expire":0}
          {"op":"close","id":<notification id>}
stdout <- {"event":"ready"}
          {"event":"notified","ref":"<any>","id":<notification id>}
          {"event":"action","id":<notification id>,"key":"<action key>"}
          {"event":"closed","id":<notification id>,"reason":<1 expired|2 dismissed|3 closed by call|4 other>}
          {"event":"error","ref":"<any>","error":".."}
"""
import json
import sys
import threading

import gi

gi.require_version("Gio", "2.0")
gi.require_version("GLib", "2.0")
from gi.repository import Gio, GLib  # noqa: E402

BUS_NAME = "org.freedesktop.Notifications"
OBJ_PATH = "/org/freedesktop/Notifications"

out_lock = threading.Lock()


def emit(obj):
    with out_lock:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()


bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
proxy = Gio.DBusProxy.new_sync(bus, Gio.DBusProxyFlags.NONE, None, BUS_NAME, OBJ_PATH, BUS_NAME, None)


def on_signal(_proxy, _sender, signal, params):
    if signal == "ActionInvoked":
        nid, key = params.unpack()
        emit({"event": "action", "id": nid, "key": key})
    elif signal == "NotificationClosed":
        nid, reason = params.unpack()
        emit({"event": "closed", "id": nid, "reason": reason})


proxy.connect("g-signal", on_signal)


def handle(cmd):
    op = cmd.get("op")
    try:
        if op == "notify":
            hints = {
                "urgency": GLib.Variant("y", int(cmd.get("urgency", 2))),
                "resident": GLib.Variant("b", bool(cmd.get("resident", True))),
                "desktop-entry": GLib.Variant("s", "cyberboba"),
            }
            icon = cmd.get("icon") or ""
            if icon and not icon.startswith("file://") and icon.startswith("/"):
                icon = "file://" + icon
            args = GLib.Variant(
                "(susssasa{sv}i)",
                (
                    "cyberboba",
                    int(cmd.get("replaces", 0)),
                    icon,
                    str(cmd.get("summary", "")),
                    str(cmd.get("body", "")),
                    [str(a) for a in cmd.get("actions", [])],
                    hints,
                    int(cmd.get("expire", 0)),
                ),
            )
            res = proxy.call_sync("Notify", args, Gio.DBusCallFlags.NONE, 5000, None)
            emit({"event": "notified", "ref": cmd.get("ref"), "id": res.unpack()[0]})
        elif op == "close":
            proxy.call_sync("CloseNotification", GLib.Variant("(u)", (int(cmd["id"]),)), Gio.DBusCallFlags.NONE, 5000, None)
        elif op == "quit":
            loop.quit()
    except Exception as exc:  # noqa: BLE001
        emit({"event": "error", "ref": cmd.get("ref"), "error": str(exc)})
    return False  # one-shot idle callback


def reader():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            cmd = json.loads(line)
        except ValueError:
            continue
        GLib.idle_add(handle, cmd)
    GLib.idle_add(loop.quit)


loop = GLib.MainLoop()
threading.Thread(target=reader, daemon=True).start()
emit({"event": "ready"})
loop.run()
