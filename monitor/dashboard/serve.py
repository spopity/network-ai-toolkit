"""Production server for the dashboard (waitress), with two listeners:

  dashboard.unix_socket  for `tailscale serve` only. Requests here carry trusted
                         Tailscale identity headers (router_agent/identity.py).
                         tailscale serve --bg --https=443 unix:<path>
                         tailscale serve --bg --http=8080 unix:<path>
  dashboard.host:port    TCP for the router's wan-event hook and Tshoot's API calls.
                         Bind it to the LAN address, NOT 127.0.0.1/0.0.0.0: with Tailscale
                         in userspace mode every 127.0.0.1 port is reachable from the
                         tailnet, which would bypass the identity check.

Without unix_socket it is a single TCP listener (no approvals possible).
`python dashboard/app.py --dev` still starts Flask's development server.
"""
import threading

from waitress import create_server

from router_agent.identity import MarkTailscale

THREADS = 8  # Tshoot chat streams hold a thread for the length of an answer


def run(app, dash_cfg: dict) -> None:
    servers = [create_server(app, host=dash_cfg.get("host", "127.0.0.1"), port=int(dash_cfg.get("port", 8080)),
                             threads=THREADS, ident="network-ai")]
    sock = dash_cfg.get("unix_socket")
    if sock:
        # only tailscale serve can connect here (socket 0660 netai, tailscaled is root), and it
        # overwrites X-Forwarded-For with the client's tailnet IP: keep the header, which
        # waitress otherwise strips from untrusted proxies
        servers.append(create_server(MarkTailscale(app), unix_socket=sock, unix_socket_perms="660",
                                     clear_untrusted_proxy_headers=False, threads=THREADS, ident="network-ai"))
    for s in servers:
        s.print_listen("network-ai dashboard listening on {}")
    for s in servers[1:]:
        threading.Thread(target=s.run, daemon=True).start()
    servers[0].run()
