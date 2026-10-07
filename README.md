# Unified VPS Panel

Unified VPS Panel is a control panel for managing a Linux VPS from a simple terminal menu and web page.

It can manage:

- SSH accounts
- VLESS accounts
- VMess accounts
- Trojan accounts
- Hysteria 2 accounts
- Backups and restores
- Server status and resource usage
- Network and port checks
- SSL certificate information
- Security tools such as Fail2Ban
- Service restarts and updates

It is designed to work mainly on Ubuntu and Debian servers.

## What you get

After installation, the VPS has:

- A command-line menu: `menu`
- A web panel on port `6080`
- SSH access
- VLESS, VMess and Trojan support through Xray
- Hysteria 2 on UDP port `53`
- Automatic backups
- A service checker that can restart important services when needed
- A daily reboot at **04:00 server local time**

## Before installing

You need:

1. A VPS running Ubuntu or Debian
2. Root access to the VPS
3. A domain or subdomain pointing to the VPS
4. An internet connection during installation

Supported systems:

- Ubuntu 22.04
- Ubuntu 24.04
- Ubuntu 26.04
- Debian 11
- Debian 12
- Debian 13

Supported CPU types:

- amd64
- arm64

## Installation

Run this on the VPS as **root**.

### Copy this command

GitHub shows a **copy button** at the top-right of this code block. Tap it, paste the command into your VPS terminal, and press Enter.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/clintonpaul19/unified-vps-panel/main/install.sh)
```

The installer will ask for the domain that points to the VPS.

Example:

```text
Domain pointing to this VPS: panel.example.com
```

Let the installer finish. It installs the required programs, configures the services, gets an SSL certificate for the domain, and checks the installation.

### After installation

Check the server:

```bash
vps-status
```

Open the management menu:

```bash
menu
```

## First-time web panel setup

There is **no default username or password**.

Open:

```text
http://YOUR-DOMAIN:6080/
```

The first page asks you to create your own login:

```text
Enter username
Enter password
Reenter password
```

After you save it, you can log in normally on future visits.

The login information is saved on the VPS at:

```text
/etc/unified-vps/admin.json
```

The file is protected so normal users cannot read it.

### Important security note

The web panel currently uses **HTTP on port 6080**, not HTTPS.

That means you should not treat `http://YOUR-DOMAIN:6080/` as a secure public login page. Use a trusted network or put the panel behind HTTPS before exposing it publicly.

## Main terminal menu

Run:

```bash
menu
```

The menu includes:

| Option | What it does |
|---|---|
| SSH accounts | Create and manage SSH users |
| VLESS accounts | Create and manage VLESS users |
| VMess accounts | Create and manage VMess users |
| Trojan accounts | Create and manage Trojan users |
| Hysteria accounts | Create and manage Hysteria 2 users |
| All accounts | See accounts from all connection types |
| Backup / restore | Save or restore server settings |
| Server information | View basic VPS information |
| Monitoring | Check services and resource usage |
| Domain & network | Check DNS, routes and network settings |
| Logs & reports | View service and security logs |
| Restart all services | Restart the main VPS services |
| Speedtest | Run Ookla Speedtest |
| Active connections | See current network connections |
| System resources | See CPU, memory, disk and uptime |
| Security audit | Check firewall, SSH, Fail2Ban and certificate status |
| Update panel / proxy files | Download the latest supported files from this repository |

## Connection types

The panel creates connection details for several protocols.

### SSH

Regular SSH uses port 22.

The server also supports SSH through the configured web-based transport ports.

### VLESS

VLESS is supported through Xray.

Typical connection:

```text
Server: YOUR-DOMAIN
Port: 80 or 443
Network: WebSocket
Path: /vless
```

The panel generates the UUID and the complete connection link for you.

### VMess

VMess is also handled by Xray.

Typical connection:

```text
Server: YOUR-DOMAIN
Port: 80 or 443
Network: WebSocket
Path: /vmess
```

The panel generates the UUID and connection link.

### Trojan

Trojan uses a password and TLS.

Typical ports:

```text
80
443
```

The panel generates the password and connection link.

### Hysteria 2

Hysteria 2 uses UDP port `53`.

The panel creates a connection link in the `hysteria2://` format.

## Main public ports

| Service | Port |
|---|---|
| SSH / shared web transport | TCP 80, 443, 143, 8080, 8443, 8880 |
| VLESS | TCP 80, 443 |
| VMess | TCP 80, 443 |
| Trojan | TCP 80, 443 |
| Hysteria 2 | UDP 53 |
| Web panel | TCP 6080 |

Some internal services use local-only ports. You normally do not need to change or open those ports.

## SSL certificate

During installation, the panel requests a trusted Let's Encrypt certificate for your domain.

The certificate files are stored on the VPS:

```text
/etc/unified-vps/xray.crt
/etc/unified-vps/xray.key
```

Certificate renewal is handled automatically.

You can also check the certificate from the terminal menu.

## Creating accounts

You can create accounts from either:

- `menu`
- The web panel

The generated account information can include:

- Username
- Password or UUID
- Server address
- Port
- Expiry date
- Connection link

The panel supports copy-ready links for VLESS, VMess, Trojan and Hysteria 2.

## Backups

The panel has built-in backups.

Backups contain important server settings and account information needed to restore the installation.

The system keeps multiple recent backups and also supports scheduled backups.

Do not upload backup files to public websites or GitHub. A backup may contain sensitive information.

## Updating

From the VPS menu:

```text
menu
→ Update panel / proxy files
```

The updater downloads all required files from one specific version of the repository, checks them before installation, and only replaces the running files after the checks succeed.

If the new panel does not start correctly, the updater can restore the previous panel version.

## Basic checks

Check the overall installation:

```bash
vps-status
```

Test the Xray configuration:

```bash
xray -test -config /usr/local/etc/xray/config.json
```

See listening ports:

```bash
ss -lntup
```

See the panel log:

```bash
journalctl -u unified-vps-panel -n 100 --no-pager
```

See failed services:

```bash
systemctl --failed
```

## If something is not working

Start with:

```bash
vps-status
```

Then check:

1. The domain points to the correct VPS IP.
2. The required port is allowed by the VPS provider's firewall.
3. The relevant service is running.
4. The certificate is valid.
5. The generated account details match the client you are using.

The VPS provider may have its own firewall or security settings in addition to the firewall on the server itself.

## Project layout

You do not need to understand the whole repository to use the panel.

The important parts are:

```text
install.sh              Main installer
scripts/menu.sh         VPS command menu
panel/                  Web panel
config/                 Service configuration
systemd/                Service definitions
scripts/                Maintenance and helper scripts
platform/               Optional multi-server control panel
deploy/                 Production deployment files
docs/                   Project documentation
```

The `platform/` directory is a separate part of the project for managing multiple VPS machines from one central system. A normal single-VPS installation does not require you to use it.

## Architecture, in simple terms

For a normal installation, the flow is roughly:

```text
Your phone / computer
        |
        v
     Your domain
        |
        v
      Your VPS
     /       \
    v         v
Web Panel   Connection services
             |   |   |   |
            SSH Xray Hysteria 2
```

The web panel lets you manage the server.

The connection services handle the accounts you create.

## Important security rules

Never:

- Commit VPS passwords, private keys or backup files to GitHub.
- Share `/etc/unified-vps/admin.json`.
- Give the panel password to someone you do not trust.
- Expose the HTTP panel publicly without understanding the security risk.
- Run the installer on a VPS you cannot afford to rebuild while testing.

## Development status

This project is actively developed.

For production use, test the installation on a fresh VPS first and keep backups before making major changes.

## License

This project is licensed under the **MIT License**.

You are free to use, copy, modify, publish, distribute, and sell the software, provided that the original copyright notice and license are included.

See [LICENSE](LICENSE) for the full license text.
