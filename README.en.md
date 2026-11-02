# SplitDirect

[中文](README.md) | **English**

Let **selected Windows programs bypass the VPN** while everything else stays on an **OpenVPN full tunnel**.

OpenVPN can only split traffic by destination IP, not by application. SplitDirect fills that gap: keep the VPN in full-tunnel mode, but let a game, a music app or one particular browser use your local network directly.

> Requires Windows 10 / 11 (64-bit) and administrator rights. Built for OpenVPN (TAP-Windows, Wintun and DCO adapters); other VPNs can be tried by choosing the adapters manually in Settings.
>
> The user interface is currently in Chinese only.

## Features

- **Per-program bypass** with three kinds of rules: a program name (`curl.exe`, every program with that name), a full path (only that exact file), or a folder (every program inside it, handy for multi-process apps installed in versioned folders)
- **Child processes too**: programs started by a listed program also bypass the VPN (games started by a launcher, `curl` / `git` run from `cmd`, …)
- **Local DNS for bypassed programs**: their DNS queries are answered by a domestic resolver over DNS-over-HTTPS (Alibaba or Tencent DNSPod, sent from the local adapter), so they get nearby servers. Works even when OpenVPN uses `block-outside-dns`
- **Domain presets** for 28 popular Chinese services (Tencent, ByteDance, Alibaba, Bilibili, …): checked domains are resolved locally for every program. Data comes from [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) and is updated weekly. A built-in tool can also capture the domains an app uses
- **Follows the VPN automatically**: disconnects, reconnects, IP changes and Wi-Fi switches are picked up within about a second
- **IPv6 handling**: when the VPN has no IPv6, IPv6 traffic from non-bypassed programs is blocked so it cannot leak around the tunnel
- **One-click self check**: admin rights, driver, adapters, local DNS, system proxy and the live status of every listed program, each with advice on how to fix problems
- **Also**: tray icon, start with Windows, pause for 30 minutes, rule export / import, dark mode, diagnostics export

## Usage

1. Download the zip from [Releases](../../releases) and extract it somewhere permanent
2. Connect your VPN with OpenVPN GUI (full-tunnel mode)
3. Run `SplitDirect.exe` (it asks for administrator rights), click **添加程序** (Add program) to choose the programs to bypass, then click **开始分流** (Start)
4. Not sure it works? Click **自检** (Self check) at the bottom, or look at the connection count shown next to each program

Closing the window keeps SplitDirect running in the tray; right-click the tray icon to pause or exit. After exiting, all traffic goes through the VPN again.

## FAQ

**I added a program but it still uses the VPN.**
- Run the self check first. The most common cause is a system proxy (set by v2rayN, Clash, …): browsers then hand their traffic to the proxy instead of connecting directly
- Programs that were already running get their old connections reset so they reconnect directly; a few programs do not reconnect by themselves — just restart them

**The program bypasses the VPN but is slow or fails to load.**
Many apps resolve domain names through the Windows system DNS, so the query still goes through the VPN to an overseas resolver and returns overseas servers. Check the matching preset under Settings → DNS, or capture the app's domains with the built-in tool and add them as custom domains.

**Browsers get overseas servers for domestic sites.**
DNS queries made by a bypassed browser are redirected to the local resolver automatically — unless the browser's "Secure DNS" is set to a specific provider (e.g. Cloudflare). Switch it to "use your current service provider".

**How do I bypass the VPN for command-line downloads (curl, git, pip)?**
Add `cmd.exe` (or `powershell.exe` / `pwsh.exe`) and enable "child processes too".

**I don't use OpenVPN.**
Choose the VPN adapter and the local adapter manually under Settings → Network adapters. Corporate VPNs such as AnyConnect or GlobalProtect often install firewall rules that block local traffic, so bypassing may not work with them.

## How it works

```
program ──(source = VPN adapter IP)──> captured by WinDivert
                                         │
             program on the bypass list? ┤
               yes: rewrite source to the local adapter IP and send it out the local adapter
               no:  pass through unchanged (goes through the VPN)
reply ──(destination = local adapter IP)──> destination rewritten back to the VPN IP, delivered to the program
```

- Packets are rewritten at the network layer with [WinDivert](https://github.com/basil00/WinDivert); programs need no configuration
- The owning process of a packet is identified from WinDivert SOCKET-layer events (the driver reports the process when a socket binds or connects), falling back to a scan of the system connection table
- DNS queries from bypassed programs to the VPN's DNS server are intercepted, resolved via DNS-over-HTTPS (port 443) from the local adapter, and answered with a reply that appears to come from the VPN's DNS server
- The driver files are copied to `C:\ProgramData\SplitDirect\windivert\` and loaded from there, so the program folder can be deleted or replaced at any time

Settings live in `%APPDATA%\SplitDirect\`; daily logs are kept for 7 days in its `logs` folder.

## Run from source / build

Requires 64-bit Python 3.10 or newer.

```bat
pip install -r requirements.txt
python gui.py            :: run from an administrator command prompt
build.bat                :: builds dist\SplitDirect\SplitDirect.exe
```

| File | Contents |
|---|---|
| `engine.py` | Core: adapter detection, packet rewriting, DNS, IPv6, process identification |
| `gui.py` | User interface (PySide6) |
| `preset_updater.py` | Parsing and online updates of the domain presets |
| `domain_presets.py` | Bundled domain presets (generated by `tools/gen_presets.py`) |

## Notes

- SplitDirect needs administrator rights and loads a network driver; some security software may block it or raise a warning
- Follow the rules of your network (school, company) and of your VPN service; some organisations require all traffic to go through their VPN
- The software is provided "as is", without warranty of any kind (see the MIT license)

## License

[MIT](LICENSE). Third-party components and their licenses are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
