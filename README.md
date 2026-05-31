# podscan

**An `/etc/hosts` for your Solid pod.** Scan your LAN for machines, detect which run a
Nostr relay (default port `4444`), resolve the verified WebID identities behind them, and
write it all into your pod's `/private` as a JSON-LD directory your web apps can read.

## Why

A browser can't scan a LAN — no raw sockets, no ARP, no ICMP. So the privileged step runs
here (where `nmap` and the filesystem live) and drops a **same-origin, owner-only** document
the pod's web apps simply `fetch`. All the LAN networking happens server-side, so discovery
works even when the app is served from `https://` GitHub Pages (the browser only reads its
own pod). Run it on a schedule (cron / systemd timer) to keep the file warm.

```
 cron / CLI (privileged)                 browser app (any origin)
   nmap LAN sweep            writes          reads, same-origin
   probe :4444 relays   ───►  /private/net/hosts.jsonld  ───►  "Local network" tab
   query kind-0 + WebID
```

## Install

```bash
npm install -g podscan      # or: npx podscan scan
# requires nmap on the host:  sudo apt install nmap
```

## Usage

```bash
podscan scan
```

Options:

| flag | default | meaning |
|---|---|---|
| `--subnet` | auto-detect | CIDR to scan, e.g. `192.168.0.0/24` |
| `--port` | `4444` | Nostr relay port to probe |
| `--pod-port` | `5444` | pod HTTP port (for WebID card resolution) |
| `--out` | `~/pod-data/private/net/hosts.jsonld` | where to write |
| `--ttl-days` | `7` | drop hosts unseen longer than this |
| `--timeout` | `5000` | per-host probe timeout (ms) |
| `--json` | — | print to stdout instead of writing the file |

Run `sudo podscan scan` for ARP-based discovery (faster, finds hosts that drop ping).

## Output

```jsonc
{
  "@context": { "lan": "urn:solid:lan#", "...": "..." },
  "@id": "#lan", "@type": "lan:LocalNetwork",
  "subnet": "192.168.0.0/24", "scannedAt": "2026-05-31T…",
  "hosts": [
    {
      "ip": "192.168.0.10", "hostname": "laptop", "mac": "00:45:e2:…",
      "firstSeen": "…", "lastSeen": "…",
      "services": [ { "@type": "lan:NostrRelay", "relay": "ws://192.168.0.10:4444", "up": true } ],
      "identities": [
        { "pubkey": "…", "name": "alice",
          "webid": "http://192.168.0.10:5444/profile/card.jsonld#me", "verified": true }
      ]
    }
  ]
}
```

A host's `identities` are **WebID-verified**: each pubkey is confirmed against that pod's
`card.jsonld` via the bidirectional link (`verificationMethod` + `authentication`) — the same
check the [solid-apps/nostr](https://github.com/solid-apps/nostr) control center uses.

## Schedule

```cron
*/10 * * * *  /usr/bin/podscan scan >> ~/.podscan.log 2>&1
```

## License

AGPL-3.0-or-later
