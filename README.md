# Unified VPS Tunnels

A simple terminal-based VPS tunnel manager for Ubuntu and Debian.

There is no web panel, web login, admin account, or browser interface.

## What it provides

- SSH
- VLESS over WebSocket
- VMess over WebSocket
- Trojan over TLS
- Hysteria 2 on UDP 53
- SSH over WebSocket/WSS
- HAProxy for public transport multiplexing
- NGINX as a local HTTP fallback
- Let's Encrypt TLS certificates
- Fail2Ban for SSH protection

UDP forwarding through BadVPN/UDPGW is not included.

## Install

Run as `root` on the VPS:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/install.sh)
```

The installer asks for the domain pointing to the VPS, installs the tunnel services, obtains a TLS certificate, and checks the required listeners.

## Configure everything from the menu

After installation:

```bash
menu
```

The menu is terminal-only.

Main functions:

| Option | Purpose |
|---|---|
| Configure domain | Set or change the tunnel domain |
| Create account | Create SSH, VLESS, VMess, Trojan, or Hysteria 2 users |
| List accounts | Show all tunnel accounts |
| Show connection details | Print passwords, UUIDs, and connection URIs |
| Enable / Disable | Turn an account on or off |
| Renew | Change account expiry |
| Delete | Remove an account |
| Tunnel status | Check services and listeners |
| Restart services | Rebuild configurations and restart tunnels |
| Data usage | Show server RX/TX totals |

## Connection endpoints

- SSH: TCP 22
- SSH WebSocket: TCP 80, 8080, 8880
- SSH WSS: TCP 443, 8443
- VLESS: TCP 80/443, WebSocket path `/vless`
- VMess: TCP 80/443, WebSocket path `/vmess`
- Trojan: TLS on TCP 443/8443
- Hysteria 2: UDP 53

Hysteria 2 supports `userpass` authentication with username/password pairs. citeturn542970search0turn542970search2

## Account storage

Tunnel account data is stored locally at:

```text
/etc/unified-vps/accounts.json
```

The directory is root-only. Passwords and protocol credentials are never written to the GitHub repository.

## TLS

The installer uses Let's Encrypt for the supplied domain.

Certificate files:

```text
/etc/unified-vps/xray.crt
/etc/unified-vps/xray.key
```

Xray receives service-local copies under `/usr/local/etc/xray/certs/`.

Certificate renewal is handled by `acme.sh`.

## Useful commands

```bash
menu
vps-status
systemctl status xray
systemctl status hysteria-server
ss -lntup
```

Test Xray:

```bash
xray -test -config /usr/local/etc/xray/config.json
```

## Repository layout

```text
install.sh
README.md
LICENSE

config/
  fail2ban-unified-vps.local
  haproxy.cfg

scripts/
  tunnel.sh
  menu.sh
  vps-status.sh
  unified-vps-cert-reload
  ws-payload-ssh.py

systemd/
  hysteria-server.service
  unified-vps-wstunnel-ssh.service
  unified-vps-ws-payload-ssh.service
```

## Security

Keep the VPS firewall restricted to the ports you actually use. Keep the TLS private key and `/etc/unified-vps/accounts.json` private.

## License

MIT
