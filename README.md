# Unified VPS Tunnels

A terminal-only VPS tunnel manager for Ubuntu and Debian.

There is no web panel, browser login, administrator web account, or TCP 6080 service.

## What it installs

- SSH
- VLESS over WebSocket
- VMess over WebSocket
- Trojan over TLS
- Hysteria 2 on UDP 53
- SSH over WebSocket/WSS
- HAProxy transport multiplexing
- Local NGINX fallback
- Let's Encrypt TLS certificates
- Fail2Ban for SSH

BadVPN/UDPGW is not included.

## Install

Run as `root`:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/install.sh)
```

Enter the domain or subdomain that points to the VPS.

The installer removes the old web-panel files and state from previous Unified VPS installations, then installs only the tunnel stack.

## Configure with `menu`

After installation:

```bash
menu
```

The menu is terminal-only and is the only account-management interface.

```text
[1] Configure domain
[2] Create account
[3] List accounts
[4] Show connection details
[5] Enable account
[6] Disable account
[7] Renew account
[8] Delete account
[9] Tunnel/service status
[10] Restart tunnel services
[11] Data usage
[12] Exit
```

Supported account types: SSH, VLESS, VMess, Trojan, and Hysteria 2.

## Endpoints

```text
SSH             TCP 22
SSH WS          TCP 80, 8080, 8880
SSH WSS         TCP 443, 8443
VLESS           TCP 80 / 443, path /vless
VMess           TCP 80 / 443, path /vmess
Trojan          TCP 443
Hysteria 2      UDP 53
```

## Account storage

Account data is stored locally on the VPS:

```text
/etc/unified-vps/accounts.json
```

The file is root-only. Protocol credentials are not stored in GitHub.

## TLS

Let's Encrypt certificates are installed at:

```text
/etc/unified-vps/xray.crt
/etc/unified-vps/xray.key
```

Xray and Hysteria use restricted service-local copies. Renewal is handled by `acme.sh`.

## Useful commands

```bash
menu
vps-status
xray -test -config /usr/local/etc/xray/config.json
systemctl status xray
systemctl status hysteria-server
ss -lntup
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

Keep the VPS firewall restricted to the ports you use. Keep the TLS private key and `/etc/unified-vps/accounts.json` private.

## License

MIT
