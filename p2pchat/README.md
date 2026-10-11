# P2P Observatory Chat

Development in progress. Python signaling/STUN/telemetry server with a separate Python WebRTC echo peer, and a shared Android/Windows/Linux UI. Strict direct mode: no TURN and no message/media relay over signaling.

## Invariants

- Signaling carries presence, offer/answer/ICE and bounded redacted diagnostics only.
- Each path has a unique connection/attempt id. Successful paths do not stop other attempts.
- Messages and test payloads only travel on a selected direct transport.
- A server echo peer is an actual participant: it only echoes to the sender, never between clients; echo messages cannot trigger another echo.
- Telemetry excludes keys, SDP credentials, raw media and message bodies. Client logs remain local when disconnected; central delivery is acknowledged and deduplicated.
- Capability labels distinguish tested, implemented-but-unverified, unsupported-platform, unavailable and deferred. No fabricated NAT support claims.
- IPv6 stateful probing is not a globally open inbound port. ICE success is checked against the selected candidate pair; relay candidates are forbidden.

Implementation and platform verification details will be recorded alongside source and tests. Existing research under ../outputs is immutable.
