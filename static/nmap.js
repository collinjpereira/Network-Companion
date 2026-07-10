/* Nmap command reference: a filterable cheat-sheet on the Port Scan tab.
   Commands are pre-filled with the target host and ports the analyst typed,
   and are copy-to-clipboard only, the tool never executes nmap itself.
   Relies on globals from app.js: $, $$, escapeHtml. */
(function () {
  const HOST = () => ($("#scan-host") && $("#scan-host").value.trim()) || "<target>";

  /* Turn the scan tab's port spec into an nmap -p / --top-ports argument. */
  function portArg() {
    const raw = (($("#scan-ports") && $("#scan-ports").value) || "").trim().toLowerCase();
    if (!raw || raw === "top100" || raw === "top-100" || raw === "top 100" || raw === "top") return "--top-ports 100";
    if (raw === "common" || raw === "quick") return "-p 21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,8080,8443";
    if (raw === "all" || raw === "full" || raw === "1-65535") return "-p-";
    return "-p " + raw.replace(/\s+/g, "");
  }

  /* Each command: { name, desc, tags, warn?, build(h, p) -> "nmap …" } */
  const GROUPS = [
    {
      cat: "Host discovery", tags: "discovery ping",
      cmds: [
        { name: "Ping sweep (no port scan)", desc: "Which hosts are up — no ports probed.", build: (h) => `nmap -sn ${h}` },
        { name: "No ping (skip discovery)", desc: "Treat host as up; good when ICMP is blocked.", build: (h, p) => `nmap -Pn ${p} ${h}` },
        { name: "List scan", desc: "List/reverse-DNS targets without sending probes.", build: (h) => `nmap -sL ${h}` },
        { name: "ARP ping (local subnet)", desc: "Fastest, most reliable discovery on a LAN.", warn: true, build: (h) => `sudo nmap -PR -sn ${h}` },
        { name: "ICMP echo ping", desc: "Classic ping probe.", warn: true, build: (h) => `sudo nmap -PE -sn ${h}` },
        { name: "ICMP timestamp + netmask ping", desc: "Alternate ICMP probes for filtered hosts.", warn: true, build: (h) => `sudo nmap -PP -PM -sn ${h}` },
        { name: "TCP SYN ping", desc: "Discovery via SYN to common ports.", warn: true, build: (h) => `sudo nmap -PS22,80,443,3389 -sn ${h}` },
        { name: "TCP ACK ping", desc: "ACK probe — slips past some stateless filters.", warn: true, build: (h) => `sudo nmap -PA80,443 -sn ${h}` },
        { name: "UDP ping", desc: "Discovery via UDP to DNS/SNMP.", warn: true, build: (h) => `sudo nmap -PU53,161 -sn ${h}` },
        { name: "SCTP INIT ping", desc: "SCTP association probe.", warn: true, build: (h) => `sudo nmap -PY -sn ${h}` },
        { name: "IP protocol ping", desc: "Probe with several IP protocols.", warn: true, build: (h) => `sudo nmap -PO -sn ${h}` },
        { name: "Traceroute to host", desc: "Map the path to the target.", warn: true, build: (h) => `sudo nmap -sn --traceroute ${h}` },
        { name: "No DNS resolution", desc: "Skip reverse DNS for speed.", build: (h, p) => `nmap -n ${p} ${h}` },
      ],
    },
    {
      cat: "Port selection & basics", tags: "basic ports",
      cmds: [
        { name: "Default scan", desc: "Top 1000 TCP ports, SYN if root else connect.", build: (h) => `nmap ${h}` },
        { name: "Fast scan (top 100)", desc: "Quick look at the 100 most common ports.", build: (h) => `nmap -F ${h}` },
        { name: "Top N ports", desc: "Scan the N most common ports.", build: (h) => `nmap --top-ports 1000 ${h}` },
        { name: "Your selected ports", desc: "Uses the port field above.", build: (h, p) => `nmap ${p} ${h}` },
        { name: "All 65,535 TCP ports", desc: "Full TCP sweep — slow but complete.", build: (h) => `nmap -p- ${h}` },
        { name: "Ports by service name", desc: "Reference ports by name.", build: (h) => `nmap -p http,https,ssh,smb ${h}` },
        { name: "Open ports only + reason", desc: "Hide closed/filtered; show why.", build: (h, p) => `nmap --open --reason ${p} ${h}` },
      ],
    },
    {
      cat: "TCP scan techniques", tags: "tcp technique stealth",
      cmds: [
        { name: "SYN / half-open (stealth)", desc: "The default when privileged; fast and quiet.", warn: true, build: (h, p) => `sudo nmap -sS ${p} ${h}` },
        { name: "TCP connect", desc: "Full 3-way handshake; no root needed.", build: (h, p) => `nmap -sT ${p} ${h}` },
        { name: "ACK (firewall mapping)", desc: "Maps filtered vs unfiltered, not open/closed.", warn: true, build: (h, p) => `sudo nmap -sA ${p} ${h}` },
        { name: "Window", desc: "ACK variant that can infer open ports.", warn: true, build: (h, p) => `sudo nmap -sW ${p} ${h}` },
        { name: "Maimon", desc: "FIN/ACK probe against some BSD stacks.", warn: true, build: (h, p) => `sudo nmap -sM ${p} ${h}` },
        { name: "NULL", desc: "No flags set — evades simple filters.", warn: true, build: (h, p) => `sudo nmap -sN ${p} ${h}` },
        { name: "FIN", desc: "FIN-only probe.", warn: true, build: (h, p) => `sudo nmap -sF ${p} ${h}` },
        { name: "Xmas", desc: "FIN+PSH+URG set.", warn: true, build: (h, p) => `sudo nmap -sX ${p} ${h}` },
        { name: "Custom TCP flags", desc: "Craft your own flag combination.", warn: true, build: (h, p) => `sudo nmap --scanflags SYNFIN ${p} ${h}` },
        { name: "Idle / zombie scan", desc: "Blind scan bounced off a zombie host.", warn: true, build: (h, p) => `sudo nmap -sI <zombie-host> ${p} ${h}` },
        { name: "FTP bounce scan", desc: "Relay a scan through an FTP server.", build: (h, p) => `nmap -b <user:pass@ftp-server> ${p} ${h}` },
      ],
    },
    {
      cat: "UDP / SCTP / IP protocol", tags: "udp sctp protocol",
      cmds: [
        { name: "UDP scan", desc: "Probe UDP services (slow; be patient).", warn: true, build: (h, p) => `sudo nmap -sU ${p} ${h}` },
        { name: "UDP top 100", desc: "Common UDP ports only — much faster.", warn: true, build: (h) => `sudo nmap -sU --top-ports 100 ${h}` },
        { name: "Combined TCP SYN + UDP", desc: "Scan both transports in one run.", warn: true, build: (h, p) => `sudo nmap -sS -sU ${p} ${h}` },
        { name: "SCTP INIT", desc: "SCTP port scan (telecom / SIGTRAN).", warn: true, build: (h, p) => `sudo nmap -sY ${p} ${h}` },
        { name: "SCTP COOKIE ECHO", desc: "Stealthier SCTP variant.", warn: true, build: (h, p) => `sudo nmap -sZ ${p} ${h}` },
        { name: "IP protocol scan", desc: "Which IP protocols the host supports.", warn: true, build: (h) => `sudo nmap -sO ${h}` },
      ],
    },
    {
      cat: "Service & version detection", tags: "version service banner sv",
      cmds: [
        { name: "Version detection", desc: "Identify service + version on open ports.", build: (h, p) => `nmap -sV ${p} ${h}` },
        { name: "Max version intensity", desc: "Try every probe (most accurate, slower).", build: (h, p) => `nmap -sV --version-intensity 9 ${p} ${h}` },
        { name: "Light version detection", desc: "Fast, likeliest probes only.", build: (h, p) => `nmap -sV --version-light ${p} ${h}` },
        { name: "Grab banners", desc: "Pull raw service banners via NSE.", build: (h, p) => `nmap -sV --script=banner ${p} ${h}` },
      ],
    },
    {
      cat: "OS detection", tags: "os fingerprint",
      cmds: [
        { name: "OS detection", desc: "TCP/IP stack fingerprinting.", warn: true, build: (h) => `sudo nmap -O ${h}` },
        { name: "OS detection + guessing", desc: "Guess aggressively when unsure.", warn: true, build: (h) => `sudo nmap -O --osscan-guess ${h}` },
        { name: "OS + version together", desc: "Fingerprint host and services.", warn: true, build: (h, p) => `sudo nmap -O -sV ${p} ${h}` },
        { name: "OS detect, limit to promising hosts", desc: "Only fingerprint hosts with open+closed ports.", warn: true, build: (h) => `sudo nmap -O --osscan-limit ${h}` },
      ],
    },
    {
      cat: "Aggressive & comprehensive", tags: "aggressive full comprehensive intense",
      cmds: [
        { name: "Aggressive scan (-A)", desc: "OS + version + default scripts + traceroute.", warn: true, build: (h, p) => `sudo nmap -A ${p} ${h}` },
        { name: "Intense scan (Zenmap)", desc: "The classic -T4 -A -v profile.", build: (h) => `nmap -T4 -A -v ${h}` },
        { name: "Intense, all TCP ports", desc: "Intense profile across every TCP port.", build: (h) => `nmap -p 1-65535 -T4 -A -v ${h}` },
        { name: "Full audit (TCP+UDP, all ports)", desc: "Deep everything scan — very slow.", warn: true, build: (h) => `sudo nmap -sS -sU -T4 -A -v -p- ${h}` },
        { name: "Full TCP + vuln scripts", desc: "Every TCP port with default + vuln NSE.", warn: true, build: (h) => `sudo nmap -sS -sV -O -p- --script "default,vuln" ${h}` },
      ],
    },
    {
      cat: "NSE — script categories", tags: "nse script category",
      cmds: [
        { name: "Default scripts (-sC)", desc: "Safe, useful default script set.", build: (h, p) => `nmap -sC ${p} ${h}` },
        { name: "Safe scripts", desc: "Non-intrusive checks only.", build: (h, p) => `nmap --script safe ${p} ${h}` },
        { name: "Vulnerability scripts", desc: "Check known vulnerabilities.", build: (h, p) => `nmap --script vuln ${p} ${h}` },
        { name: "CVE lookup (vulners)", desc: "Map detected versions to CVEs.", build: (h, p) => `nmap -sV --script vulners ${p} ${h}` },
        { name: "Discovery scripts", desc: "Enumerate hosts, services, and info.", build: (h, p) => `nmap --script discovery ${p} ${h}` },
        { name: "Auth scripts", desc: "Test default/empty credentials.", build: (h, p) => `nmap --script auth ${p} ${h}` },
        { name: "Brute-force scripts", desc: "Credential guessing — loud and intrusive.", warn: true, build: (h, p) => `nmap --script brute ${p} ${h}` },
        { name: "Malware / backdoor scripts", desc: "Detect known backdoors.", build: (h, p) => `nmap --script malware ${p} ${h}` },
        { name: "Exploit scripts", desc: "Actively exploit — authorised targets only.", warn: true, build: (h, p) => `nmap --script exploit ${p} ${h}` },
        { name: "Intrusive scripts", desc: "May crash or disrupt the target.", warn: true, build: (h, p) => `nmap --script intrusive ${p} ${h}` },
        { name: "DoS scripts", desc: "Denial-of-service tests — extreme caution.", warn: true, build: (h, p) => `nmap --script dos ${p} ${h}` },
        { name: "Update script database", desc: "Refresh the NSE script index.", warn: true, build: () => `sudo nmap --script-updatedb` },
        { name: "Script with arguments", desc: "Pass arguments to a script.", build: (h) => `nmap --script http-enum --script-args http-enum.basepath=/ ${h}` },
        { name: "Trace script activity", desc: "See every packet a script sends.", build: (h, p) => `nmap --script vuln --script-trace ${p} ${h}` },
      ],
    },
    {
      cat: "NSE — targeted by service", tags: "nse smb http tls ssh dns ftp sql snmp rdp service",
      cmds: [
        { name: "SMB: OS discovery", desc: "Host/OS details over SMB.", build: (h) => `nmap -p445 --script smb-os-discovery ${h}` },
        { name: "SMB: enumerate shares & users", desc: "List shares and accounts.", build: (h) => `nmap -p445 --script smb-enum-shares,smb-enum-users ${h}` },
        { name: "SMB: EternalBlue (MS17-010)", desc: "Check for the MS17-010 vulnerability.", build: (h) => `nmap -p445 --script smb-vuln-ms17-010 ${h}` },
        { name: "SMB: all vuln checks", desc: "Every smb-vuln-* script.", build: (h) => `nmap -p445 --script "smb-vuln-*" ${h}` },
        { name: "SMB: supported protocols", desc: "SMBv1/2/3 dialects offered.", build: (h) => `nmap -p445 --script smb-protocols ${h}` },
        { name: "HTTP: enumerate dirs/files", desc: "Discover web content.", build: (h) => `nmap -p80,443 --script http-enum ${h}` },
        { name: "HTTP: title, headers, methods", desc: "Fingerprint the web server.", build: (h) => `nmap -p80,443 --script http-title,http-headers,http-methods ${h}` },
        { name: "HTTP: vulnerability checks", desc: "All http-vuln-* scripts.", build: (h) => `nmap -p80,443 --script "http-vuln-*" ${h}` },
        { name: "HTTP: WAF detection", desc: "Detect/fingerprint a web firewall.", build: (h) => `nmap -p80,443 --script http-waf-detect,http-waf-fingerprint ${h}` },
        { name: "TLS: enumerate ciphers", desc: "Grade SSL/TLS cipher suites.", build: (h) => `nmap -p443 --script ssl-enum-ciphers ${h}` },
        { name: "TLS: certificate details", desc: "Show the server certificate.", build: (h) => `nmap -p443 --script ssl-cert ${h}` },
        { name: "TLS: Heartbleed", desc: "Test for CVE-2014-0160.", build: (h) => `nmap -p443 --script ssl-heartbleed ${h}` },
        { name: "SSH: algorithms & host key", desc: "Enumerate SSH crypto + key.", build: (h) => `nmap -p22 --script ssh2-enum-algos,ssh-hostkey ${h}` },
        { name: "SSH: auth methods", desc: "Which authentication methods are offered.", build: (h) => `nmap -p22 --script ssh-auth-methods ${h}` },
        { name: "DNS: zone transfer", desc: "Attempt AXFR (set your domain).", build: (h) => `nmap -p53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=<domain> ${h}` },
        { name: "FTP: anonymous + backdoor", desc: "Anonymous login and vsftpd backdoor.", build: (h) => `nmap -p21 --script ftp-anon,ftp-vsftpd-backdoor ${h}` },
        { name: "MySQL: info & empty password", desc: "Server info and blank-root check.", build: (h) => `nmap -p3306 --script mysql-info,mysql-empty-password ${h}` },
        { name: "MSSQL: info & empty password", desc: "SQL Server details.", build: (h) => `nmap -p1433 --script ms-sql-info,ms-sql-empty-password ${h}` },
        { name: "RDP: encryption & NTLM info", desc: "RDP security posture.", build: (h) => `nmap -p3389 --script rdp-ntlm-info,rdp-enum-encryption ${h}` },
        { name: "SMTP: users, commands, relay", desc: "Enumerate mail server.", build: (h) => `nmap -p25 --script smtp-enum-users,smtp-commands,smtp-open-relay ${h}` },
        { name: "SNMP: info & community brute", desc: "SNMP enumeration (UDP).", warn: true, build: (h) => `sudo nmap -sU -p161 --script snmp-info,snmp-brute ${h}` },
        { name: "NFS: exports & listing", desc: "Show mounts and files.", build: (h) => `nmap -p2049 --script nfs-showmount,nfs-ls ${h}` },
        { name: "Redis / MongoDB info", desc: "Unauthenticated DB info.", build: (h) => `nmap -p6379,27017 --script redis-info,mongodb-info,mongodb-databases ${h}` },
        { name: "VNC: info & auth bypass", desc: "VNC security checks.", build: (h) => `nmap -p5900 --script vnc-info,realvnc-auth-bypass ${h}` },
        { name: "LDAP: root DSE", desc: "Directory server base info.", build: (h) => `nmap -p389 --script ldap-rootdse ${h}` },
      ],
    },
    {
      cat: "Timing & performance", tags: "timing speed rate T0 T5",
      cmds: [
        { name: "Paranoid timing (-T0)", desc: "IDS evasion; extremely slow.", build: (h, p) => `nmap -T0 ${p} ${h}` },
        { name: "Sneaky / Polite (-T1/-T2)", desc: "Low-and-slow to reduce load.", build: (h, p) => `nmap -T2 ${p} ${h}` },
        { name: "Normal / Aggressive (-T3/-T4)", desc: "-T4 is the usual fast default.", build: (h, p) => `nmap -T4 ${p} ${h}` },
        { name: "Insane timing (-T5)", desc: "Fastest; may lose accuracy.", build: (h, p) => `nmap -T5 ${p} ${h}` },
        { name: "Set packet rate", desc: "Floor/ceiling on packets per second.", build: (h, p) => `nmap --min-rate 1000 --max-rate 5000 ${p} ${h}` },
        { name: "Retries & host timeout", desc: "Cap retransmits and per-host time.", build: (h, p) => `nmap --max-retries 2 --host-timeout 30m ${p} ${h}` },
        { name: "Scan delay", desc: "Pause between probes to dodge rate limits.", build: (h, p) => `nmap --scan-delay 1s ${p} ${h}` },
        { name: "Parallelism / host groups", desc: "Tune concurrency.", build: (h, p) => `nmap --min-parallelism 10 --min-hostgroup 64 ${p} ${h}` },
      ],
    },
    {
      cat: "Firewall / IDS evasion & spoofing", tags: "evasion firewall spoof decoy fragment stealth",
      cmds: [
        { name: "Fragment packets", desc: "Split probes into tiny fragments.", warn: true, build: (h, p) => `sudo nmap -f ${p} ${h}` },
        { name: "Custom MTU", desc: "Fragment to a specific size (multiple of 8).", warn: true, build: (h, p) => `sudo nmap --mtu 16 ${p} ${h}` },
        { name: "Decoy scan", desc: "Hide among spoofed decoy sources.", warn: true, build: (h, p) => `sudo nmap -D RND:10 ${p} ${h}` },
        { name: "Spoof source IP", desc: "Forge the source address (needs -e + -Pn).", warn: true, build: (h, p) => `sudo nmap -S <spoofed-ip> -e eth0 -Pn ${p} ${h}` },
        { name: "Spoof MAC address", desc: "Random, vendor, or specific MAC.", warn: true, build: (h, p) => `sudo nmap --spoof-mac 0 ${p} ${h}` },
        { name: "Source port / -g", desc: "Send from a trusted port like 53 or 443.", warn: true, build: (h, p) => `sudo nmap --source-port 53 ${p} ${h}` },
        { name: "Append random data", desc: "Pad probes past signature lengths.", warn: true, build: (h, p) => `sudo nmap --data-length 25 ${p} ${h}` },
        { name: "Bad checksum probes", desc: "Reveal firewalls that ignore checksums.", warn: true, build: (h, p) => `sudo nmap --badsum ${p} ${h}` },
        { name: "Custom TTL", desc: "Set the IP time-to-live.", warn: true, build: (h, p) => `sudo nmap --ttl 64 ${p} ${h}` },
        { name: "Randomize host order", desc: "Shuffle target order across a range.", build: (h, p) => `nmap --randomize-hosts ${p} ${h}` },
        { name: "Proxy chain", desc: "Relay through HTTP/SOCKS proxies.", build: (h, p) => `nmap --proxies http://proxy:8080 ${p} ${h}` },
      ],
    },
    {
      cat: "Output, targets & misc", tags: "output save file ipv6 targets format",
      cmds: [
        { name: "Save all formats (-oA)", desc: "Normal, XML and grepable at once.", build: (h, p) => `nmap ${p} -oA scan_${(HOST() === "<target>" ? "target" : HOST().replace(/[^\w.-]/g, "_"))} ${h}` },
        { name: "Normal / XML / grepable", desc: "Pick a single output format.", build: (h, p) => `nmap ${p} -oN scan.txt -oX scan.xml -oG scan.gnmap ${h}` },
        { name: "Verbose + reason + open", desc: "Readable live output.", build: (h, p) => `nmap -v --reason --open ${p} ${h}` },
        { name: "Packet trace (debug)", desc: "Print every packet sent/received.", build: (h, p) => `nmap --packet-trace ${p} ${h}` },
        { name: "Scan targets from a file", desc: "Read a host list; exclude some.", build: () => `nmap -iL targets.txt --excludefile exclude.txt` },
        { name: "Exclude a host", desc: "Skip specific targets in a range.", build: (h, p) => `nmap ${p} --exclude 10.0.0.1 ${h}` },
        { name: "IPv6 scan", desc: "Scan an IPv6 target.", build: (h, p) => `nmap -6 ${p} ${h}` },
        { name: "Specific interface / send-eth", desc: "Force interface and raw ethernet frames.", warn: true, build: (h, p) => `sudo nmap -e eth0 --send-eth ${p} ${h}` },
        { name: "Resume an aborted scan", desc: "Continue from a grepable log.", build: () => `nmap --resume scan.gnmap` },
        { name: "Progress stats", desc: "Print progress every 10 seconds.", build: (h, p) => `nmap --stats-every 10s ${p} ${h}` },
      ],
    },
  ];

  function matches(cmd, group, query) {
    if (!query) return true;
    const hay = (cmd.name + " " + cmd.desc + " " + group.cat + " " + group.tags).toLowerCase();
    return query.toLowerCase().split(/\s+/).every(t => hay.includes(t));
  }

  function render() {
    const groupsEl = $("#nmap-groups");
    if (!groupsEl) return;
    const h = HOST(), p = portArg();
    const targetEl = $("#nmap-target");
    if (targetEl) targetEl.innerHTML = `target <b>${escapeHtml(h)}</b> · ports <b>${escapeHtml(p)}</b>`;

    const query = ($("#nmap-filter") && $("#nmap-filter").value.trim()) || "";
    const catFilter = ($("#nmap-cat") && $("#nmap-cat").value) || "";

    let html = "", shown = 0;
    GROUPS.forEach(group => {
      if (catFilter && group.cat !== catFilter) return;
      const cmds = group.cmds.filter(c => matches(c, group, query));
      if (!cmds.length) return;
      html += `<div class="nmap-group"><div class="nmap-group-head">${escapeHtml(group.cat)}</div>`;
      cmds.forEach(c => {
        const line = c.build(h, p).replace(/\s+/g, " ").trim();
        shown++;
        html += `<div class="nmap-cmd">` +
          `<div class="nc-desc"><b>${escapeHtml(c.name)}.</b> ${escapeHtml(c.desc)}</div>` +
          `<div class="nc-line">${escapeHtml(line)}</div>` +
          `<div class="tagrow">${c.warn ? '<span class="nc-tag nc-warn">needs sudo / intrusive</span>' : ""}</div>` +
          `<button type="button" class="btn btn-ghost nc-copy">Copy</button>` +
          `</div>`;
      });
      html += `</div>`;
    });
    groupsEl.innerHTML = shown ? html : `<div class="nmap-empty">No commands match that filter.</div>`;
  }

  /* copy handler (delegated) */
  document.addEventListener("click", e => {
    const btn = e.target.closest(".nc-copy");
    if (!btn) return;
    const line = btn.closest(".nmap-cmd").querySelector(".nc-line");
    if (!line) return;
    navigator.clipboard.writeText(line.textContent).then(() => {
      const o = btn.textContent; btn.textContent = "Copied";
      setTimeout(() => btn.textContent = o, 1200);
    });
  });

  /* populate category dropdown + wire inputs */
  function init() {
    const sel = $("#nmap-cat");
    if (sel) GROUPS.forEach(g => { const o = document.createElement("option"); o.value = g.cat; o.textContent = g.cat; sel.appendChild(o); });
    ["#scan-host", "#scan-ports", "#nmap-filter"].forEach(id => {
      const el = $(id); if (el) el.addEventListener("input", render);
    });
    if (sel) sel.addEventListener("change", render);
    render();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
