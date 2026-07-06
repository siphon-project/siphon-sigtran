"""scp.py, a CAMEL SCP: answer initialDP with a connect.

The gsmSSF triggers initialDP; we terminate it, decide a new destination, and
answer with a Connect in the closing dialogue. Load it into a siphon binary that
has mounted the siphon-sigtran namespaces.
"""

from siphon import gsm_cap


@gsm_cap.on_initial_dp
async def on_idp(dlg, idp):
    target = reroute(idp.called_party_number)  # your routing logic
    dlg.invoke(gsm_cap.connect(destination_routing_address=[target]))
    dlg.end()  # connect in the closing dialogue


def reroute(called_party_number):
    """Map the dialled number to a new destination (called-party-number bytes).

    Here a fixed reroute; replace with your own logic (a portability dip, a
    time-of-day plan, a per-subscriber service)."""
    _ = called_party_number
    return b"\x00\x15\x55\x01\x99"
