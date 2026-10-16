"""Shared interpretation of a single server-to-client HTTP callback."""

SCOPE = "this-observer-this-tcp-port-this-time-not-udp-or-all-peers"

MESSAGES = {
    "REACHABLE": "IPv6 HTTP callback reached the client and verified its one-time token.",
    "TIMEOUT_INCONCLUSIVE": "IPv6 HTTP callback timed out; firewall blocking is possible, not proven.",
    "OBSERVER_NO_ROUTE": "The server has no IPv6 route; client firewall status is unknown.",
    "OBSERVER_SOURCE_UNAVAILABLE": "The server cannot select a usable IPv6 source address; check its network or container configuration. Client firewall status is unknown.",
    "OBSERVER_OR_DESTINATION_UNREACHABLE": "Server or destination IPv6 is unreachable; firewall status is unknown.",
    "CONNECTION_REFUSED": "IPv6 TCP connection was refused; a rejecting firewall or listener failure is possible.",
    "CONNECT_FAILED": "IPv6 TCP connection failed; client firewall status is unknown.",
    "TOKEN_MISMATCH": "An HTTP response arrived but did not authenticate this client listener.",
    "REJECTED_BY_POLICY": "The server rejected the callback by policy; no firewall conclusion is available.",
    "LISTENER_REACHED_OBSERVER_RESPONSE_FAILED": "The client received the authenticated callback, but the server did not confirm the response.",
    "INCONSISTENT_OBSERVER_AND_LISTENER": "Server and listener evidence disagree; do not treat this as reachability proof.",
    "CONTROL_RESULT_TIMEOUT": "No callback result arrived over signaling; client firewall status is unknown.",
    "LOCAL_LISTENER_OR_SIGNALING_FAILED": "The local listener or signaling failed; no firewall conclusion is available.",
    "LOCAL_ADDRESS_NOT_AVAILABLE": "The IPv6 address disappeared or is not eligible for a new connection; no firewall conclusion is available.",
}


def assessment(code):
    if code == "REACHABLE":
        return "HTTP_ALLOWED_FOR_THIS_PROBE"
    if code == "LISTENER_REACHED_OBSERVER_RESPONSE_FAILED":
        return "INBOUND_REQUEST_RECEIVED_RESPONSE_UNCONFIRMED"
    if code in ("REJECTED_BY_POLICY", "LOCAL_ADDRESS_NOT_AVAILABLE"):
        return "NOT_TESTED"
    return "INCONCLUSIVE"


def message(code):
    return MESSAGES.get(code, "IPv6 HTTP callback result is unrecognized; firewall status is unknown.")
