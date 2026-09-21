# Unified VPS Panel

All-in-one VPS management panel for Hysteria 2, Xray, SSH, SSH WebSocket/WSS, BadVPN and unified CLI/web management.

## Installation

### Fresh VPS — recommended

Run as root:

```bash
curl -fsSL https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/install.sh | bash
```

Or with wget:

```bash
wget -qO- https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/install.sh | bash
```

If you are logged in as a normal user with sudo:

```bash
curl -fsSL https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/install.sh | sudo bash
```

### After installation

Check the server:

```bash
vps-status
```

Open the CLI management menu:

```bash
menu
```

Show the generated panel credentials:

```bash
cat /etc/unified-vps/panel.env
```

The web panel uses port **2087** by default:

```text
http://SERVER_IP:2087
```

### Supported operating systems

- Ubuntu 22.04
- Ubuntu 24.04
- Ubuntu 26.04
- Debian 11
- Debian 12
- Debian 13

Supported architectures:

- amd64
- arm64

### Default ports

| Service | Port |
|---|---:|
| SSH | TCP 22 |
| DNS/Hysteria | UDP 53 |
| SSH WebSocket | TCP 80 |
| SSH WSS | TCP 443 |
| Unified Panel | TCP 2087 |
| Xray VMess | TCP 10086 |
| Xray VLESS | TCP 10087 |
| Xray Trojan | TCP 10088 |
| BadVPN UDPGW | UDP 7100–7300 |

## Important

The project is currently under development. Test it on a fresh VPS before using it for production workloads.

Do not expose or commit `/etc/unified-vps/panel.env`; it contains the generated panel administrator password.
