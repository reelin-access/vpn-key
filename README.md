# vpn-key

The Reelin VPN key page: one static page, served by GitHub Pages at <https://reelin-access.github.io/vpn-key/>, that makes the WireGuard key pair for a new VPN device inside the browser, shows the public key for the Access Request, and saves the device's complete configuration file, `reelin.conf`. Nothing the page makes or reads leaves the browser.

## What the page does

1. The person types the VPN address the approver gave them. The page takes only `10.8.0.2` to `10.8.0.254`: the pool is `10.8.0.0/24`, and `.0`, `.1` (the hub) and `.255` are never a device's.
2. **Make my key** makes an X25519 key pair with the browser's WebCrypto. The private key is the JWK `d`, clamped as `wg genkey` clamps it; the public key is the JWK `x`. Both are base64 with padding, 44 characters ending in `=`.
3. The page shows the public key with a **Copy** button. The private key goes only into the file **Save reelin.conf** downloads; the page shows it nowhere, logs nothing and stores nothing. After the download the page drops the file, so a lost file means a new key: reload and start again.
4. Below the steps, the page says what comes next: the public key into the request form (or to the approver on Teams for a person without GitHub), then Windows (import the file into WireGuard) or Ubuntu (install the file as `/etc/wireguard/wg0.conf`).

A browser without WebCrypto X25519 gets one line, to use a current Chrome, Edge, Firefox or Safari, and nothing else.

The page loads nothing: its CSS and JavaScript are inline, and its Content-Security-Policy (`default-src 'none'`, `connect-src 'none'`, `form-action 'none'`, `base-uri 'none'`, with inline script and style and `data:` images for the empty tab icon) forbids every request. Links to the request form and to WireGuard's download page open in a new tab.

## Where the values come from

`reelin.conf` is:

```
[Interface]
PrivateKey = <made in the browser>
Address = <the address typed>/32
DNS = 10.8.0.1

[Peer]
PublicKey = qh+qUrZtbgsMm4A7qxGmSGHn+BiOi42uHCuxFFEpLFU=
AllowedIPs = 10.8.0.0/24, 10.80.0.0/16
Endpoint = vpn.reelinrobotics.com:51820
PersistentKeepalive = 25
```

| Value | Source |
|---|---|
| `PublicKey` under `[Peer]` | `hub-key` in `settings.txt` of `reelin-access/registers` |
| `DNS`, and the address the page refuses as the hub's | `hub-address` in `settings.txt` |
| The address range the page accepts | `pool` in `settings.txt` |
| `AllowedIPs`, `Endpoint`, `PersistentKeepalive` | The client settings every Reelin VPN device uses: the VPN itself and the routed site networks, the hub's public name and port |

None of these is secret. When one of them changes in the registers or on the hub, `index.html` changes with it, and so does its test.

## Testing

`tests/test_page.py` loads the page from `file://` in Playwright's Chromium and checks that:

- the page requests nothing but itself and writes nothing to the console, and its policy refuses a request;
- a bad address is refused, and `10.8.0.2` and `10.8.0.254` are taken;
- the downloaded `reelin.conf` holds exactly the lines above, with a clamped 44-character private key that `wg pubkey` maps to the public key the page shows, and the private key is nowhere on the page;
- a browser without X25519 is sent to a current browser.

It needs Python 3 with `playwright` and its Chromium (`python3 -m playwright install chromium`), and `/usr/bin/wg` (`wireguard-tools`). From the repository:

```
TMPDIR=<a directory of your own> python3 -m unittest tests.test_page
```

The test writes the downloaded file, and with it a private key, only into a temporary directory it deletes at the end, and never prints the key. `TMPDIR` decides where that directory and the browser's profile live.
