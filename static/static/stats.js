/* Statistics tab: everything here is computed client-side from
   state.packets, so it reflects whatever is loaded, a live capture or an
   opened PCAP. Relies on globals defined in app.js: $, $$, state,
   escapeHtml, flagEmoji, flagByIp, hostByIp. */

/* Service names for the destination-port table. Mirrors the labels the
   backend uses in capture.py so a port maps to something readable. */
const STAT_TCP_SERVICES = {
  20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
  80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 587: "SMTP",
  993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
  5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP", 8443: "HTTPS",
};
const STAT_UDP_SERVICES = {
  53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 123: "NTP", 137: "NBNS",
  161: "SNMP", 162: "SNMP", 500: "IKE", 514: "Syslog", 1900: "SSDP", 5353: "mDNS",
};

function humanBytes(n) {
  n = +n || 0;
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n < 10 ? 2 : 1) + " " + u[i];
}
function humanDuration(sec) {
  sec = Math.max(0, +sec || 0);
  if (sec < 1) return (sec * 1000).toFixed(0) + " ms";
  if (sec < 60) return sec.toFixed(2) + " s";
  const m = Math.floor(sec / 60), s = Math.round(sec % 60);
  if (m < 60) return m + "m " + s + "s";
  const h = Math.floor(m / 60);
  return h + "h " + (m % 60) + "m";
}
function statNum(n) { return (+n || 0).toLocaleString(); }

/* Packets these statistics should be computed over: the main capture, plus
   NC Traffic (Network Companion's own traffic) when the analyst opts in via
   the "Include NC Traffic" toggle. Relies on ncState from app.js. */
function currentStatsPackets() {
  const toggle = document.getElementById("stats-include-nc");
  if (toggle && toggle.checked && typeof ncState !== "undefined") {
    return state.packets.concat(ncState.packets);
  }
  return state.packets;
}

/* IP cell that reuses the flag + reverse-DNS data the capture view collects.
   Clickable: applies a `host <ip>` display filter and jumps to Capture. */
function statIpCell(ip) {
  if (!ip) return '<span class="st-ip dim">-</span>';
  const cc = flagByIp[ip];
  const flag = (cc && cc !== "PRIVATE") ? flagEmoji(cc) + " " : "";
  const label = (state.resolveDns && hostByIp[ip]) ? hostByIp[ip] : ip;
  const title = ' title="Filter the capture by ' + escapeHtml(ip) + '"';
  return '<span class="st-ip clickable" data-capfilter="host ' + escapeHtml(ip) + '"' + title + ">" + flag + escapeHtml(label) + "</span>";
}

/* Apply a display filter to the live capture table and switch to it. */
function applyCaptureFilter(expr) {
  const input = $("#display-filter");
  if (input) input.value = expr;
  if (typeof updateDisplayFilter === "function") updateDisplayFilter(expr);
  if (typeof activateTab === "function") activateTab("capture");
}

document.addEventListener("click", e => {
  const el = e.target.closest("[data-capfilter]");
  if (!el || !$("#panel-stats").classList.contains("active")) return;
  applyCaptureFilter(el.dataset.capfilter);
});

/* ---------- generic sortable table ----------
   Two header columns can share a data key (e.g. "Packets" and "% packets"),
   so sorting is tracked by the header's column index, resolved to a key. */
const STATS_TABLES = {};

function statsTable(mountId, columns, rows, defaultSort, limit) {
  let st = STATS_TABLES[mountId];
  const defIdx = Math.max(0, columns.findIndex(c => c.key === defaultSort.key && c.sortable !== false));
  if (!st) { st = STATS_TABLES[mountId] = { activeIdx: defIdx, key: defaultSort.key, dir: defaultSort.dir }; }
  st.columns = columns; st.rows = rows; st.limit = limit || 0;
  if (st.activeIdx == null || st.activeIdx >= columns.length || columns[st.activeIdx].sortable === false) {
    st.activeIdx = defIdx; st.key = defaultSort.key; st.dir = defaultSort.dir;
  } else {
    st.key = columns[st.activeIdx].key;
  }
  drawStatsTable(mountId);
}

function drawStatsTable(mountId) {
  const st = STATS_TABLES[mountId];
  const columns = st.columns, rows = st.rows, key = st.key, dir = st.dir, limit = st.limit;
  const col = columns.find(c => c.key === key) || columns[0];
  const sorted = rows.slice().sort((a, b) => {
    let av = a[key], bv = b[key];
    if (col.num) { av = +av || 0; bv = +bv || 0; return dir === "asc" ? av - bv : bv - av; }
    av = String(av == null ? "" : av); bv = String(bv == null ? "" : bv);
    return dir === "asc" ? av.localeCompare(bv) : bv.localeCompare(av);
  });
  const shown = limit ? sorted.slice(0, limit) : sorted;
  const maxByKey = {};
  columns.forEach(c => { if (c.bar) maxByKey[c.key] = Math.max(1, ...rows.map(r => +r[c.key] || 0)); });

  let html = '<table class="stats-table"><thead><tr>';
  columns.forEach((c, idx) => {
    const sortable = c.sortable !== false;
    const isActive = idx === st.activeIdx;
    const aria = isActive ? ' aria-sort="' + (dir === "asc" ? "ascending" : "descending") + '"' : "";
    const arrow = isActive ? (dir === "asc" ? " ▲" : " ▼") : "";
    const cls = ((c.align === "num" ? "num" : "") + (sortable ? " sortable" : "")).trim();
    html += '<th data-idx="' + idx + '" class="' + cls + '"' + aria + ">" + escapeHtml(c.label) + arrow + "</th>";
  });
  html += "</tr></thead><tbody>";
  shown.forEach(r => {
    html += "<tr>";
    columns.forEach(c => {
      const raw = r[c.key];
      const disp = c.fmt ? c.fmt(raw, r) : escapeHtml(String(raw == null ? "" : raw));
      const align = c.align === "num" ? "num" : "";
      if (c.bar) {
        const pct = (+raw || 0) / maxByKey[c.key] * 100;
        html += '<td class="' + align + ' bar-cell"><span class="bar" style="width:' + pct.toFixed(1) + '%"></span><span class="bar-v">' + disp + "</span></td>";
      } else {
        html += '<td class="' + align + '">' + disp + "</td>";
      }
    });
    html += "</tr>";
  });
  if (!shown.length) html += '<tr><td class="dim" colspan="' + columns.length + '">No data.</td></tr>';
  html += "</tbody></table>";

  const mount = document.getElementById(mountId);
  mount.innerHTML = html;
  mount.querySelectorAll("th.sortable").forEach(th => th.addEventListener("click", () => {
    const idx = +th.dataset.idx, c = columns[idx];
    if (st.activeIdx === idx) st.dir = st.dir === "asc" ? "desc" : "asc";
    else { st.activeIdx = idx; st.key = c.key; st.dir = c.num ? "desc" : "asc"; }
    drawStatsTable(mountId);
  }));
}

/* ---------- compute ---------- */
function computeStats(pkts) {
  const endpoints = {}, convos = {}, protos = {}, ports = {};
  let totalBytes = 0, flagged = 0, minT = Infinity, maxT = -Infinity;

  for (const p of pkts) {
    const len = +p.length || 0;
    totalBytes += len;
    if (typeof p.epoch === "number") { if (p.epoch < minT) minT = p.epoch; if (p.epoch > maxT) maxT = p.epoch; }
    if (p.threat && p.threat.level && p.threat.level !== "none") flagged++;

    const pr = protos[p.proto] || (protos[p.proto] = { proto: p.proto, packets: 0, bytes: 0 });
    pr.packets++; pr.bytes += len;

    if (p.src) { const e = endpoints[p.src] || (endpoints[p.src] = { ip: p.src, txPkts: 0, rxPkts: 0, txBytes: 0, rxBytes: 0 }); e.txPkts++; e.txBytes += len; }
    if (p.dst) { const e = endpoints[p.dst] || (endpoints[p.dst] = { ip: p.dst, txPkts: 0, rxPkts: 0, txBytes: 0, rxBytes: 0 }); e.rxPkts++; e.rxBytes += len; }

    if (p.src && p.dst) {
      const forward = p.src <= p.dst;
      const a = forward ? p.src : p.dst, b = forward ? p.dst : p.src;
      const ckey = a + " " + b;
      const c = convos[ckey] || (convos[ckey] = { a: a, b: b, abPkts: 0, abBytes: 0, baPkts: 0, baBytes: 0 });
      if (forward) { c.abPkts++; c.abBytes += len; } else { c.baPkts++; c.baBytes += len; }
    }

    if ((p.transport === "tcp" || p.transport === "udp") && p.dport != null) {
      const pkey = p.transport + ":" + p.dport;
      const svc = (p.transport === "tcp" ? STAT_TCP_SERVICES : STAT_UDP_SERVICES)[p.dport] || "";
      const pt = ports[pkey] || (ports[pkey] = { port: p.dport, transport: p.transport.toUpperCase(), service: svc, packets: 0, bytes: 0 });
      pt.packets++; pt.bytes += len;
    }
  }

  const endpointList = Object.values(endpoints).map(e => Object.assign({}, e, {
    totalPkts: e.txPkts + e.rxPkts, totalBytes: e.txBytes + e.rxBytes,
  }));
  const convoList = Object.values(convos).map(c => Object.assign({}, c, {
    packets: c.abPkts + c.baPkts, bytes: c.abBytes + c.baBytes,
  }));
  const duration = (isFinite(minT) && isFinite(maxT)) ? Math.max(0, maxT - minT) : 0;

  return {
    count: pkts.length, totalBytes: totalBytes, flagged: flagged, duration: duration,
    protos: Object.values(protos), endpoints: endpointList,
    convos: convoList, ports: Object.values(ports),
  };
}

/* ---------- render ---------- */
function renderStats() {
  const pkts = currentStatsPackets();

  const tag = $("#source-tag");
  let source = state.running ? "Live capture" : "Capture";
  if (tag && !tag.hidden && tag.textContent) source = tag.textContent;
  $("#st-source").textContent = source;

  const empty = $("#stats-empty"), content = $("#stats-content");
  if (!pkts.length) { empty.hidden = false; content.hidden = true; return; }
  empty.hidden = true; content.hidden = false;

  const s = computeStats(pkts);
  const dur = s.duration;
  const avgSize = s.count ? Math.round(s.totalBytes / s.count) : 0;
  const pps = dur > 0 ? s.count / dur : 0;
  const bps = dur > 0 ? s.totalBytes / dur : 0;

  const tiles = [
    { k: "Packets", v: statNum(s.count) },
    { k: "Total bytes", v: humanBytes(s.totalBytes), sub: statNum(s.totalBytes) + " B" },
    { k: "Duration", v: humanDuration(dur) },
    { k: "Avg packet", v: avgSize + " <em>B</em>" },
    { k: "Avg rate", v: Math.round(pps) + " <em>pkt/s</em>", sub: humanBytes(bps) + "/s" },
    { k: "Endpoints", v: statNum(s.endpoints.length), cls: "accent" },
    { k: "Conversations", v: statNum(s.convos.length), cls: "accent" },
    { k: "Flagged", v: statNum(s.flagged), cls: s.flagged ? "warn" : "" },
  ];
  $("#summary-grid").innerHTML = tiles.map(t =>
    '<div class="summary-tile ' + (t.cls || "") + '"><span class="tile-k">' + t.k + "</span>" +
    '<span class="tile-v">' + t.v + "</span>" + (t.sub ? '<span class="tile-sub">' + escapeHtml(t.sub) + "</span>" : "") + "</div>"
  ).join("");

  const totalPkts = s.count || 1, totalBytes = s.totalBytes || 1;
  const pct = n => (n / totalPkts * 100).toFixed(1) + "%";
  const pctB = n => (n / totalBytes * 100).toFixed(1) + "%";

  $("#proto-sub").textContent = s.protos.length + " protocols";
  statsTable("proto-table", [
    { key: "proto", label: "Protocol", fmt: v => '<span class="st-proto">' + escapeHtml(v) + "</span>" },
    { key: "packets", label: "Packets", align: "num", num: true, bar: true, fmt: v => statNum(v) },
    { key: "packets", label: "% packets", align: "num", num: true, sortable: false, fmt: v => '<span class="dim">' + pct(v) + "</span>" },
    { key: "bytes", label: "Bytes", align: "num", num: true, fmt: v => humanBytes(v) },
    { key: "bytes", label: "% bytes", align: "num", num: true, sortable: false, fmt: v => '<span class="dim">' + pctB(v) + "</span>" },
  ], s.protos, { key: "packets", dir: "desc" });

  $("#ep-sub").innerHTML = s.endpoints.length + ' addresses · <span class="stats-hint-click">click an address to filter the capture</span>';
  statsTable("endpoints-table", [
    { key: "ip", label: "Address", fmt: statIpCell },
    { key: "totalPkts", label: "Packets", align: "num", num: true, bar: true, fmt: v => statNum(v) },
    { key: "txPkts", label: "Tx pkts", align: "num", num: true, fmt: v => statNum(v) },
    { key: "rxPkts", label: "Rx pkts", align: "num", num: true, fmt: v => statNum(v) },
    { key: "totalBytes", label: "Total bytes", align: "num", num: true, fmt: v => humanBytes(v) },
    { key: "txBytes", label: "Tx bytes", align: "num", num: true, fmt: v => humanBytes(v) },
    { key: "rxBytes", label: "Rx bytes", align: "num", num: true, fmt: v => humanBytes(v) },
  ], s.endpoints, { key: "totalPkts", dir: "desc" }, 200);

  $("#conv-sub").innerHTML = s.convos.length + ' pairs · <span class="stats-hint-click">click either address to filter</span>';
  statsTable("conv-table", [
    { key: "a", label: "Address A", fmt: statIpCell },
    { key: "b", label: "Address B", fmt: statIpCell },
    { key: "packets", label: "Packets", align: "num", num: true, bar: true, fmt: v => statNum(v) },
    { key: "bytes", label: "Bytes", align: "num", num: true, fmt: v => humanBytes(v) },
    { key: "abPkts", label: "A→B pkts", align: "num", num: true, fmt: v => statNum(v) },
    { key: "baPkts", label: "B→A pkts", align: "num", num: true, fmt: v => statNum(v) },
  ], s.convos, { key: "packets", dir: "desc" }, 200);

  $("#ports-sub").innerHTML = s.ports.length + ' destination ports (TCP/UDP) · <span class="stats-hint-click">click a port to filter</span>';
  statsTable("ports-table", [
    { key: "port", label: "Port", align: "num", num: true, fmt: v => '<span class="st-ip clickable" data-capfilter="port ' + (+v || 0) + '" title="Filter the capture by port ' + (+v || 0) + '">' + statNum(v) + "</span>" },
    { key: "transport", label: "L4", fmt: v => '<span class="dim">' + escapeHtml(v) + "</span>" },
    { key: "service", label: "Service", fmt: v => v ? escapeHtml(v) : '<span class="dim">-</span>' },
    { key: "packets", label: "Packets", align: "num", num: true, bar: true, fmt: v => statNum(v) },
    { key: "bytes", label: "Bytes", align: "num", num: true, fmt: v => humanBytes(v) },
  ], s.ports, { key: "packets", dir: "desc" }, 100);
}

$("#stats-refresh").addEventListener("click", renderStats);
const statsIncludeNc = $("#stats-include-nc");
if (statsIncludeNc) statsIncludeNc.addEventListener("change", renderStats);
setInterval(() => {
  if (!$("#panel-stats").classList.contains("active")) return;
  if (state.running && $("#stats-auto").checked) renderStats();
}, 2000);

/* ---------- capture-statistics report ---------- */
function statsSourceLabel() {
  const tag = $("#source-tag");
  if (tag && !tag.hidden && tag.textContent) return tag.textContent;
  return state.running ? "Live capture" : "Capture";
}

function statsReportHtml(s, forWord) {
  const THEME = { heading: "#1b2a4a", accent: "#1f6f6c", gray: "#666666", cell: "#cccccc" };
  const footerNote = "Generated with Network Companion";
  const stamp = new Date().toISOString().slice(0, 16).replace("T", " ") + " UTC";
  const dur = s.duration, avg = s.count ? Math.round(s.totalBytes / s.count) : 0;
  const pps = dur > 0 ? Math.round(s.count / dur) : 0;

  const tiles = [
    ["Packets", statNum(s.count)], ["Total bytes", humanBytes(s.totalBytes)],
    ["Duration", humanDuration(dur)], ["Avg packet", avg + " B"],
    ["Avg rate", pps + " pkt/s"], ["Endpoints", statNum(s.endpoints.length)],
    ["Conversations", statNum(s.convos.length)], ["Flagged packets", statNum(s.flagged)],
  ];

  function tbl(title, cols, rows) {
    let h = `<h1>${escapeHtml(title)}</h1><table class="data"><thead><tr>` +
      cols.map(c => `<th>${escapeHtml(c)}</th>`).join("") + `</tr></thead><tbody>`;
    rows.forEach(r => { h += "<tr>" + r.map(c => `<td>${escapeHtml(String(c))}</td>`).join("") + "</tr>"; });
    return h + `</tbody></table>`;
  }

  const protoRows = s.protos.slice().sort((a, b) => b.packets - a.packets)
    .map(p => [p.proto, statNum(p.packets), (p.packets / (s.count || 1) * 100).toFixed(1) + "%", humanBytes(p.bytes)]);
  const epRows = s.endpoints.slice().sort((a, b) => b.totalPkts - a.totalPkts).slice(0, 100)
    .map(e => [e.ip, statNum(e.totalPkts), statNum(e.txPkts), statNum(e.rxPkts), humanBytes(e.totalBytes), humanBytes(e.txBytes), humanBytes(e.rxBytes)]);
  const convRows = s.convos.slice().sort((a, b) => b.packets - a.packets).slice(0, 100)
    .map(c => [c.a, c.b, statNum(c.packets), humanBytes(c.bytes), statNum(c.abPkts), statNum(c.baPkts)]);
  const portRows = s.ports.slice().sort((a, b) => b.packets - a.packets).slice(0, 60)
    .map(p => [p.port, p.transport, p.service || "-", statNum(p.packets), humanBytes(p.bytes)]);

  const msoHF = forWord ? `
    <!--[if gte mso 9]><xml><w:WordDocument><w:View>Print</w:View></w:WordDocument></xml><![endif]-->
    <div style='mso-element:header' id=h1><p class=MsoHeader style='border-bottom:.75pt solid ${THEME.heading}'>
      <span style='color:${THEME.heading};font-weight:bold'>Network Companion</span><span style='mso-tab-count:1'></span>Capture Statistics</p></div>
    <div style='mso-element:footer' id=f1><p class=MsoFooter style='border-top:.75pt solid ${THEME.heading};font-size:8pt;color:${THEME.gray}'>
      ${escapeHtml(footerNote)}<span style='mso-tab-count:1'></span>Page <span style='mso-field-code:PAGE'></span></p></div>` : "";
  const style = `
    @page Section1 { size: 8.5in 11in; margin: 1in; ${forWord ? "mso-header:h1; mso-footer:f1;" : ""} }
    div.Section1 { page: Section1; }
    * { box-sizing: border-box; }
    body { font-family: Calibri, "Segoe UI", Arial, sans-serif; color: #1a1a1a; font-size: 11pt; margin: 0; background: #fff; }
    .page { ${forWord ? "" : "max-width: 8.5in; margin: 0 auto; padding: 1in;"} }
    .doc-header { display: flex; justify-content: space-between; border-bottom: 1px solid ${THEME.heading}; padding-bottom: 4px; margin-bottom: 20px; font-size: 10pt; }
    .doc-header .brand { color: ${THEME.heading}; font-weight: bold; }
    .title-block { text-align: center; margin-bottom: 22px; }
    .title-block h1 { font-size: 26pt; font-weight: bold; color: ${THEME.heading}; margin: 0; border: none; }
    .title-rule { height: 3px; background: ${THEME.accent}; width: 60%; margin: 8px auto 6px; }
    .title-block .sub { font-size: 11pt; color: ${THEME.gray}; }
    h1 { font-size: 16pt; font-weight: bold; color: ${THEME.heading}; border-bottom: 1px solid ${THEME.heading}; padding-bottom: 3px; margin: 20px 0 10px; }
    .tiles { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 8px; }
    .tile { border: 1px solid ${THEME.cell}; border-radius: 6px; padding: 8px 12px; min-width: 120px; }
    .tile .k { font-size: 8.5pt; color: ${THEME.gray}; text-transform: uppercase; letter-spacing: .04em; }
    .tile .v { font-size: 15pt; font-weight: bold; color: ${THEME.heading}; }
    table.data { border-collapse: collapse; width: 100%; margin: 6px 0 14px; }
    table.data th { background: ${THEME.heading}; color: #fff; text-align: left; padding: 5px 8px; font-size: 9pt; border: 1px solid ${THEME.cell}; }
    table.data td { border: 1px solid ${THEME.cell}; padding: 4px 8px; font-size: 9pt; color: #000; }
    table.data tr:nth-child(even) td { background: #f9f9f9; }
    .doc-footer { margin-top: 22px; border-top: 1px solid ${THEME.heading}; padding-top: 6px; font-size: 8pt; color: ${THEME.gray}; }
    @media print { .page { padding: 0; max-width: none; } }
  `;
  return `<!DOCTYPE html><html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns="http://www.w3.org/TR/REC-html40">
<head><meta charset="utf-8"><title>Capture Statistics</title>${msoHF}<style>${style}</style></head>
<body><div class="Section1"><div class="page">
  <div class="doc-header"><span class="brand">Network Companion</span><span>Capture Statistics</span></div>
  <div class="title-block"><h1>Capture Statistics Report</h1><div class="title-rule"></div>
    <div class="sub">${escapeHtml(statsSourceLabel())} &nbsp;&middot;&nbsp; generated ${escapeHtml(stamp)}</div></div>
  <h1>Summary</h1><div class="tiles">${tiles.map(t => `<div class="tile"><div class="k">${escapeHtml(t[0])}</div><div class="v">${escapeHtml(String(t[1]))}</div></div>`).join("")}</div>
  ${tbl("Protocol breakdown", ["Protocol", "Packets", "% packets", "Bytes"], protoRows)}
  ${tbl("Endpoints (top 100 by packets)", ["Address", "Packets", "Tx pkts", "Rx pkts", "Total bytes", "Tx bytes", "Rx bytes"], epRows)}
  ${tbl("Conversations (top 100 by packets)", ["Address A", "Address B", "Packets", "Bytes", "A->B", "B->A"], convRows)}
  ${tbl("Top destination ports", ["Port", "L4", "Service", "Packets", "Bytes"], portRows)}
  <div class="doc-footer">${escapeHtml(footerNote)}</div>
</div></div></body></html>`;
}

function statsCsv(s) {
  const q = v => { const t = String(v == null ? "" : v); return /[",\n]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t; };
  const line = arr => arr.map(q).join(",");
  const out = [];
  out.push("# Network Companion capture statistics");
  out.push("# source," + q(statsSourceLabel()) + ",generated," + new Date().toISOString());
  out.push("# packets," + s.count + ",bytes," + s.totalBytes + ",endpoints," + s.endpoints.length + ",conversations," + s.convos.length + ",flagged," + s.flagged);
  out.push("");
  out.push("[Protocols]");
  out.push(line(["protocol", "packets", "bytes"]));
  s.protos.slice().sort((a, b) => b.packets - a.packets).forEach(p => out.push(line([p.proto, p.packets, p.bytes])));
  out.push("");
  out.push("[Endpoints]");
  out.push(line(["address", "total_packets", "tx_packets", "rx_packets", "total_bytes", "tx_bytes", "rx_bytes"]));
  s.endpoints.slice().sort((a, b) => b.totalPkts - a.totalPkts).forEach(e => out.push(line([e.ip, e.totalPkts, e.txPkts, e.rxPkts, e.totalBytes, e.txBytes, e.rxBytes])));
  out.push("");
  out.push("[Conversations]");
  out.push(line(["address_a", "address_b", "packets", "bytes", "a_to_b_packets", "b_to_a_packets"]));
  s.convos.slice().sort((a, b) => b.packets - a.packets).forEach(c => out.push(line([c.a, c.b, c.packets, c.bytes, c.abPkts, c.baPkts])));
  out.push("");
  out.push("[Ports]");
  out.push(line(["port", "transport", "service", "packets", "bytes"]));
  s.ports.slice().sort((a, b) => b.packets - a.packets).forEach(p => out.push(line([p.port, p.transport, p.service, p.packets, p.bytes])));
  return out.join("\n");
}

function statsDownload(name, mime, content) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

(function () {
  const btnP = $("#stats-print"), btnS = $("#stats-save"), btnC = $("#stats-csv");
  function noData() {
    if (!currentStatsPackets().length) { alert("No packets to report yet. Start a capture or open a PCAP first."); return true; }
    return false;
  }
  const stamp = () => new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
  if (btnP) btnP.addEventListener("click", () => {
    if (noData()) return;
    const html = statsReportHtml(computeStats(currentStatsPackets()), false);
    const w = window.open("", "_blank");
    if (!w) { alert("Pop-up blocked. Allow pop-ups to print, or use Save report."); return; }
    w.document.open(); w.document.write(html); w.document.close(); w.focus();
    setTimeout(() => { try { w.print(); } catch (e) {} }, 400);
  });
  if (btnS) btnS.addEventListener("click", () => {
    if (noData()) return;
    statsDownload("capture-stats-" + stamp() + ".html", "text/html;charset=utf-8", statsReportHtml(computeStats(currentStatsPackets()), false));
  });
  if (btnC) btnC.addEventListener("click", () => {
    if (noData()) return;
    statsDownload("capture-stats-" + stamp() + ".csv", "text/csv;charset=utf-8", statsCsv(computeStats(currentStatsPackets())));
  });
})();
