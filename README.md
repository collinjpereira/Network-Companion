# Network Companion

A packet analyzer, packet crafter, and IP threat-intel console in one sleek
local UI — run it as a web app in your browser, or as a native desktop app on
Windows. Built for SOC analysts doing malware triage and for network admins
who want to sniff a link quickly.

<img width="1521" height="840" alt="Photo" src="https://github.com/user-attachments/assets/b6255ccd-a8a8-442e-9339-2ad5e714027c" />

## Contents

- [What it does](#what-it-does)
- [Requirements](#requirements)
- [Install & run](#install--run)
- [Finding suspicious traffic quickly](#finding-suspicious-traffic-quickly)
- [Keeping Network Companion's own traffic out of your capture](#keeping-network-companions-own-traffic-out-of-your-capture)
- [Tagging and coloring IPs](#tagging-and-coloring-ips)
- [Using it from another computer](#using-it-from-another-computer)
- [Country flags and IP intel need internet](#country-flags-and-ip-intel-need-internet)
- [Intercept / ARP](#capturing-traffic-from-another-device-on-your-lan-intercept--arp)
- [Scope and intent](#scope-and-intent)
- [Notes and limits](#notes-and-limits)
- [Project layout](#project-layout)

## What it does

1. **Live capture** with a fast, protocol-coloured packet table, full layer
   decode, and a hex view. Times are shown in US Eastern (ET). Export any
   session to a standard `.pcap`.
2. **Country flags** next to public IPs in the capture table (local addresses
   are left unflagged), resolved and cached in the background.
3. **Threat flagging.** Every packet is run through lightweight heuristics and
   flagged inline (amber/orange/red) with plain-English reasons: NULL / FIN /
   XMAS scans, illegal flag combinations, backdoor / C2 ports, cleartext
   protocols, long or high-entropy DNS queries (possible tunnelling), and simple
   port-scan / host-sweep detection. A "Flagged only" button filters the table.
   These are heuristics to draw your eye, not a full IDS.
4. **Process attribution.** Click a packet to see which local process owns the
   socket (useful for spotting a beaconing program). This only works for the
   host running Network Companion, not for other devices.
5. **Send to Crafter.** From any selected packet, one click populates the
   crafter with its addresses, ports, flags, and TTL so you can replay or mutate
   it.
6. **Packet crafting** for custom TCP / UDP / ICMP packets and raw layer-2
   frames, with presets and a preview.
7. **Detection rule maker.** From a selected packet, generate a Suricata / Snort
   rule and a Splunk SPL search, ready to copy.
8. **IP intel** with geolocation, flag, ISP / org / ASN, hosting and proxy/VPN
   flags, and a one-click **AbuseIPDB report link** (`abuseipdb.com/check/<ip>`).
   If you add a free AbuseIPDB API key, an inline confidence gauge and report
   categories are shown too.
9. **NC Traffic tab.** Network Companion generates some real traffic of its
   own — IP-intel lookups, reverse-DNS for "Resolve names", its own UI, and
   (best-effort) packets from the Port Scan / Transfer tools. That traffic is
   automatically diverted into its own **NC Traffic** tab instead of
   flooding your capture, and is left out of the exported `.pcap` by
   default. It still gets the full treatment, though: click a row for the
   same layer/hex/threat/process detail view as the main capture, with
   working Replay and Send to Crafter. See "Keeping Network Companion's own
   traffic out of your capture" below. Packets sent from the **Crafter**
   itself (including Replay) are exempt from this — they show up in the
   normal capture like any other traffic, since when you're using the
   Crafter that traffic usually *is* the thing you're trying to watch.
10. **Per-IP tags and colors.** Right-click an address in the capture table
    to color it, tag it, and leave a description. Tagged IPs get a small dot
    next to the flag and a colored row marker everywhere they appear, and the
    note is saved to `ip_notes.json` so it survives a restart. A full list
    lives under IP Intel → Saved IPs.

The UI is served on `127.0.0.1` only.

## Requirements

- Linux, macOS, or Windows
- Python 3.9+
- Root / administrator (raw sockets need it)
- Windows only: [Npcap](https://npcap.com/), for raw packet access

## Install & run

Two ways to run it, same backend and UI either way — pick one:

| | Platforms | What you get |
|---|---|---|
| **[Desktop app](#desktop-app-windows)** | Windows only | A real window, no browser, no terminal after setup |
| **[Web app](#web-app-linux-macos-windows)** | Linux, macOS, Windows | A local server you open in your browser |

### Desktop app (Windows)

> **TL;DR:** Download `NetworkCompanionSetup.exe`, install [Npcap](https://npcap.com/)
> once if you haven't already, run the installer, done. No Python, no pip,
> no build tools — Npcap is the only separate thing Windows users need.

Most people just need one file: `NetworkCompanionSetup.exe`
(`packaging\windows\Output\NetworkCompanionSetup.exe` in this repo, or
whatever copy someone handed you). It's a normal Windows installer — no
Python, no pip, no build tools needed on the machine that runs it.

**How to run it:**

**1.** Install [Npcap](https://npcap.com/) first, if it isn't already on
that machine. This is the one thing the installer can't do for you — it's
a system driver (not a Python package), so PyInstaller can't bundle it into
the app. Use the default options during Npcap setup.

**2.** Double-click `NetworkCompanionSetup.exe` and click through the
installer. It installs to Program Files with its own icon, adds a Start
Menu entry, adds a Desktop shortcut (you can uncheck this box if you don't
want it), and registers a normal uninstaller (Settings → Apps).

**3.** When it finishes, it offers to launch Network Companion right away —
or open it later from the Desktop/Start Menu shortcut.

**4.** Windows will show a UAC prompt on first launch (every launch,
actually) — click **Yes**. Packet capture needs administrator rights; this
is expected, not a warning sign.

That's it — after that it's a normal window, no terminal, no console.
To remove it later: Settings → Apps → Network Companion → Uninstall.

#### Building the installer yourself

Only needed if you're building `NetworkCompanionSetup.exe` for others to
run, or you've changed the code. Requires Python 3.9+ and
[Inno Setup](https://jrsoftware.org/isinfo.php) (its compiler, `iscc.exe`,
needs to be on `PATH`) in addition to Npcap.

```bat
pip install -r requirements.txt -r requirements-desktop.txt
packaging\windows\build.bat
```

This produces `dist\Network Companion.exe` (the standalone app) and
`packaging\windows\Output\NetworkCompanionSetup.exe` (the installer to hand
out). If Inno Setup isn't on `PATH`, only the first is built.

> Prefer to skip building entirely? Just run `python desktop.py` — no
> installer, no packaging, straight from source.

### Web app (Linux, macOS, Windows)

**1.** Get the code and set up a virtual environment:
```bash
cd network-companion
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

**2.** Run it.

Linux/macOS:
```bash
chmod +x run.sh
sudo ./run.sh
```

Windows (install [Npcap](https://npcap.com/) first, then run this terminal
as Administrator):
```bat
python -m uvicorn main:app --host 127.0.0.1 --port 8787
```

**3.** Open **http://127.0.0.1:8787** in a browser.

Without root/Administrator the UI still loads and IP intel still works;
capture, packet sending, process attribution, and Intercept all need it.

## Finding suspicious traffic quickly

The capture bar has a **Threat presets** dropdown that fills the BPF capture
filter with ready-made expressions: SYN / NULL / XMAS / FIN scans, RST storms,
common backdoor and C2 ports, cleartext logins, DNS, SMB/RDP, cleartext HTTP,
ICMP, and ARP. Pick one, then start the capture. These are capture-time filters
(header, port, and flag level); the deeper signals come from the inline threat
flagging on each row.

The **Resolve names** toggle turns reverse-DNS name resolution on and off. Off
by default, because lookups generate their own DNS traffic from this host and
can be slow. When on, IPs in the table are replaced by hostnames (the raw IP
stays in the tooltip); when off, you see raw IPs.

## Keeping Network Companion's own traffic out of your capture

When you capture on a real interface, Network Companion's own background
activity shows up on the wire like anything else: IP-intel lookups to
ip-api.com / AbuseIPDB, reverse-DNS queries from the **Resolve names**
toggle, the browser↔server UI traffic, and (best-effort) packets sent by the
Port Scan and Transfer tools. All of that is automatically recognized and
routed into the **NC Traffic** tab instead of the main Capture table, so it
doesn't flood the view of the traffic you actually came to look at. Traffic
sent from the **Crafter** (including Replay) is deliberately left out of
this — it lands in the main Capture table like anything else, since that's
usually the traffic you're actively trying to watch.

- **Excluded from the saved capture by default.** `Export .pcap` only ever
  contains the main Capture table — NC Traffic is a separate buffer, not a
  filter, so there's nothing to accidentally leak into your evidence.
- **Want it anyway?** Use **Export all traffic .pcap** next to the normal
  export button to save both the main capture and NC Traffic merged back
  into one chronological `.pcap`.
- **Clean up as you go.** The NC Traffic tab has its own `Clear` button, and
  you can right-click a row there to delete just that packet.
- **Don't want to see it at all?** The `Hide NC Traffic` toggle next to
  "Resolve names" hides the tab and its counter from the UI. This is purely
  cosmetic — classification and the buffer keep running underneath, so
  toggling it back on picks up where it left off.
- **Full packet inspection still works.** NC Traffic isn't a dead-end table —
  click any row for the same detail pane as the main Capture tab (layers,
  hex dump, threat heuristics, local process, generated Suricata/Splunk
  rules), plus working `Send to Crafter` and `Replay` buttons.
- **Want it in the Statistics tab too?** The `Include NC Traffic` toggle
  there folds NC Traffic's packets into the summary tiles, protocol/endpoint/
  conversation/port tables, and the Print/Save/CSV reports. Off by default,
  so the numbers match what you'd get from the exported `.pcap` unless you
  opt in.
- **What isn't covered:** `netdiscover`'s ARP/ping sweep (ARP has no port to
  key off, and blanket-matching it would also hide real ARP traffic from
  other hosts during a promiscuous capture), the Intercept (MITM) feature's
  relayed traffic (deliberately left visible since seeing the victim's real
  traffic is the entire point of that tool), and anything sent from the
  Crafter (by design — see above). Port scans (connect-scan) and file
  transfers are classified best-effort: the OS picks the local port before
  Python regains control, so the handshake may land in the main capture even
  though the rest of the flow is correctly diverted; a SYN scan is fully
  reliable since Network Companion chooses the source port itself before
  sending.

## Tagging and coloring IPs

Right-click any source or destination address in the capture table (or in
NC Traffic) for options to color it, add free-form tags, and leave a
description. The IP gets a small colored dot next to its flag and a colored
marker on every row it appears in, live, for the rest of the session. Notes
are saved to `ip_notes.json` next to `main.py`, so they persist across
restarts; a full list with edit/delete is on the **IP Intel** tab under
**Saved IPs**.

## Using it from another computer

By default the server binds to `127.0.0.1`, so it is only reachable on the VM
itself. There are two ways to reach it from another machine.

**Recommended: an SSH tunnel.** Leave the bind address alone and, from the other
computer, forward the port over SSH:

```bash
ssh -L 8787:127.0.0.1:8787 you@your-vm
```

Then browse to http://127.0.0.1:8787 on that computer. Nothing is exposed on the
network, no code changes, and the traffic is encrypted. This is the safest
option and needs no auth.

**Direct hosting on the network.** If you would rather reach it by the VM's IP,
bind to all interfaces and set a password. This tool sends packets as root and
has no login of its own, so do **not** run it network-exposed without `NC_AUTH`,
and never put it on an untrusted network or the internet.

```bash
sudo NC_HOST=0.0.0.0 NC_AUTH="analyst:choose-a-strong-password" ./run.sh
```

Then from the other computer open `http://<vm-ip>:8787` and log in with those
credentials. For defence in depth, also firewall the port to the one client IP
that needs it, for example:

```bash
sudo ufw allow from <client-ip> to any port 8787 proto tcp
```

`NC_HOST`, `NC_PORT`, and `NC_AUTH` are read by both `run.sh` and a direct
`uvicorn` launch.

## Country flags and IP intel need internet

Flags use ip-api.com's bulk endpoint (cached); IP intel uses ip-api.com and,
optionally, AbuseIPDB. In a fully offline VM these degrade gracefully: flags are
simply omitted and the intel tab reports lookup failures, while capture,
crafting, threat flagging, and process attribution all work with no network.
For **offline flags**, drop a MaxMind `GeoLite2-Country.mmdb` beside the app and
switch `intel.batch_country` to read it (a small change; left as an opt-in).

## Capturing traffic from another device on your LAN (Intercept / ARP)

The **Intercept** tab does real ARP-cache poisoning: it tells the target that
this machine is its gateway (and, optionally, tells the gateway that this
machine is the target), turns on IP forwarding for the duration so the target
stays online while its traffic routes through this host, and heals both ARP
caches and restores forwarding the moment you stop (also done automatically on
server shutdown, so it never leaves a network mid-poison). Once traffic is
flowing through this host, the normal capture engine sees it like anything
else — start a capture on the same interface (the "Capture this target" button
does this for you) and it lands in the live table and PCAP export.

This is a genuine on-path (MITM) attack technique, not a toy. **Only ever point
it at a device you own or a network/engagement you're explicitly authorised to
test** — intercepting someone else's traffic without consent (a roommate's
laptop, another player's console, a guest on your Wi-Fi) is illegal in most
places and is exactly the kind of use this tool is not for. The UI requires an
explicit confirmation naming the target before it will start.

**If it seems like nothing is happening:** the interface returns `forwarding_ok`
and a list of `warnings` (shown inline in the Intercept tab) precisely because
the most common failure mode is silent — poisoning succeeds but the target's
traffic is never actually relayed. Concretely:

- **Not running with root/administrator** — Scapy can't open a raw socket to
  resolve MACs or send poisoned ARP replies, and the UI now reports this as
  "needs sudo" instead of the misleading "target didn't answer."
- **IP forwarding didn't turn on.** Handled precisely on Linux (the real
  `/proc/sys/net/ipv4/ip_forward` value is read, set, and restored). On macOS
  and Windows it's best-effort (`sysctl` / `netsh`); if it can't be confirmed,
  a warning says so rather than pretending it worked.
- **Target and gateway must be different, reachable, real devices** — the tool
  now refuses to poison this machine's own address, and refuses to proceed if
  a resolved MAC turns out to be this machine's own MAC (usually means the IPs
  were mixed up).

If you'd rather not touch ARP at all, there are consent-clean alternatives that
give full visibility into a device you own:

- **Put the analysis box in the path.** Share your laptop's connection or run a
  small Linux box / Raspberry Pi / travel router as the access point or gateway
  the device connects through, then capture on that interface.
- **Port mirroring / SPAN** on a managed switch, mirroring the device's port to
  the analysis host's port.
- **Capture at the router** if it supports it (many do; OpenWrt can run tcpdump
  or mirror a port).

## Scope and intent

For authorised use: your own hosts, your own segment, your lab, and IDS /
firewall validation you're permitted to run. The crafter sends real packets, so
point it only at systems you own or have permission to test.

## Notes and limits

- Focused tool, not a Wireshark replacement for deep dissection. It decodes the
  common stack (Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP, DNS) and gives raw
  bytes for the rest; export the `.pcap` for exotic protocols.
- Threat flags and generated rules are heuristics / starting points. Review
  before acting on them or deploying a rule.
- Process attribution is a live-socket snapshot; short-lived flows may not match.
- Live table shows the most recent 5,000 rows; the backend keeps the full
  session for export.

## Project layout

```
network-companion/
├── main.py                FastAPI server: UI, REST API, WebSocket stream
├── capture.py             Scapy capture engine + packet serialisation
├── threat.py              heuristic threat scoring + scan detection
├── procmap.py             local process attribution (psutil)
├── crafter.py             builds and sends custom packets
├── intel.py               geolocation, abuse, and batch country flags
├── mitm.py                ARP-poisoning Intercept engine + traffic shaping (tc)
├── scan.py                TCP connect / SYN port scanning
├── netdiscover.py         local-subnet ARP/ping sweep + device-type guesses
├── transfer.py            raw TCP/TLS/FTP send-data and file-transfer tools
├── selftraffic.py         registry Network Companion's own senders mark before
│                          sending, so capture.py can divert that traffic to NC Traffic
├── ipnotes.py             loads/saves per-IP tags, colors, and descriptions
├── ip_notes.json          the saved-IP notes themselves (created on first save)
├── run.sh                 root-check launcher (browser / web-app mode)
├── desktop.py             Windows desktop-app launcher (pywebview window, self-elevating)
├── requirements.txt
├── requirements-desktop.txt   extra deps for desktop.py and its packaged build
├── packaging/
│   └── windows/           PyInstaller spec, Inno Setup installer, app icon,
│                          and build.bat producing NetworkCompanionSetup.exe
└── static/                index.html, style.css, app.js, and per-tab scripts
                           (stats.js, nmap.js, ir.js, netscan.js, mitm.js)
```
