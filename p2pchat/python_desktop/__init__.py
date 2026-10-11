"""Pure-Python Tkinter desktop client. Strictly direct-only: no relay, no TURN.

The package reuses :mod:`p2pchat.peer` (WebRTC/ICE and the authenticated echo) and
:mod:`p2pchat.native` (UDP probe, QUIC, TCP, TCP simultaneous-open) in-process.
There is no stdio bridge, no Electron main process and no asar packaging here.
"""
from .version import VERSION, capabilities_report

__all__ = ["VERSION", "capabilities_report"]
