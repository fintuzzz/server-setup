# server-setup

Scripts that prepare a clean Ubuntu 24.04 server. Each command downloads what it needs and verifies checksums, so nothing
has to be copied to the server by hand. Pin `<ref>` to a commit to get exactly the files you reviewed.

```bash
curl -fsSL https://raw.githubusercontent.com/fintuzzz/server-setup/<ref>/relay.sh | sudo SETUP_REF=<ref> bash
```

| Script | Purpose |
| --- | --- |
| `check.sh` | Read-only check of a server: network, ports, reachability |
| `node.sh` | Docker and project checkout on a server with AmneziaWG. Needs `SETUP_REPO=owner/name` and `SETUP_TARGET=/path` |
| `control.sh` | Docker and project checkout on a management server. Same variables |
| `relay.sh` | Packet forwarding and tunnel without Docker |
| `probe.sh` | Availability probe without Docker |

See `NOTICE.md` for third-party binaries and their licenses.
