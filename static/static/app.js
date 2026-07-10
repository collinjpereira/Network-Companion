/* Network Companion front-end */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

const ET_FMT = new Intl.DateTimeFormat("en-US", {
  timeZone: "America/New_York", hour12: false,
  hour: "2-digit", minute: "2-digit", second: "2-digit",
});
function etTime(epoch) {
  const ms = String(Math.floor((epoch % 1) * 1000)).padStart(3, "0");
  return ET_FMT.format(new Date(epoch * 1000)) + "." + ms;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function isPrivateIp(ip) {
  if (!ip) return true;
  if (ip.includes(":")) return ip === "::1" || ip.startsWith("fe80") || ip.startsWith("fc") || ip.startsWith("fd");
  const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return true;
  const a = +m[1], b = +m[2];
  return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254);
}
function flagEmoji(cc) {
  if (!cc || cc.length !== 2) return "";
  return cc.toUpperCase().replace(/./g, c => String.fromCodePoint(127397 + c.charCodeAt(0)));
}

/* ---------- tabs ---------- */
let gmapAutoTried = false;
function activateTab(name) {
  $$(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
  $$(".panel").forEach(p => p.classList.toggle("active", p.id === "panel-" + name));
  if (name === "capture" || name === "nc") {
    // The packet detail pane (layers/hex/threat/process/rules) is a single
    // shared element, physically moved into whichever of Capture / NC
    // Traffic is showing, so both get full packet inspection for free
    // without duplicating that markup or its rendering logic.
    const targetBody = document.querySelector("#panel-" + name + " .capture-body");
    const splitter = $("#detail-splitter"), detail = $("#detail");
    if (targetBody && splitter && detail && splitter.parentElement !== targetBody) {
      targetBody.appendChild(splitter);
      targetBody.appendChild(detail);
    }
  }
  if (name === "intel") {
    if (map) setTimeout(() => map.invalidateSize(), 60);
    if (gmapInstance) setTimeout(() => gmapInstance.invalidateSize(), 60);
    else if (!gmapAutoTried && state.packets.length) { gmapAutoTried = true; plotGlobalMap(); }
    renderSavedIps();
  }
  if (name === "stats") renderStats();
}
$$(".tab").forEach(tab => tab.addEventListener("click", () => activateTab(tab.dataset.tab)));

/* ============================================================
   CAPTURE
   ============================================================ */
const state = {
  running: false, paused: false,
  packets: [], buffer: [], selected: null, selectedDetail: null,
  flaggedOnly: false, resolveDns: false,
  displayPredicate: () => true,
  protoCounts: {}, rateWindow: [],
  maxRows: 5000,
  ipNotes: {},
};

const PROTO_COLOR = {
  TCP: "#5b9dff", UDP: "#35c77e", ICMP: "#f5b544", DNS: "#a78bfa",
  ARP: "#8b97ad", HTTP: "#3dd6d0", HTTPS: "#3dd6d0",
};

const flagByIp = {};
const pendingFlags = new Set();
const hostByIp = {};
const pendingNames = new Set();

const els = {
  body: $("#pkt-body"), scroll: $("#rows-scroll"), empty: $("#table-empty"),
  count: $("#s-count"), rate: $("#s-rate"), protoBar: $("#proto-bar"),
  status: $("#status"), captureBtn: $("#capture-btn"), captureLabel: $("#capture-label"),
};

async function loadInterfaces() {
  try {
    const r = await fetch("/api/interfaces");
    const data = await r.json();
    const sel = $("#iface"); sel.innerHTML = "";
    const craft = $("#craft-iface");
    (data.interfaces || []).forEach(i => {
      const label = i.name + (i.ip ? " · " + i.ip : "");
      const o = document.createElement("option");
      o.value = i.name; o.textContent = label;
      sel.appendChild(o);
      if (craft) { const o2 = document.createElement("option"); o2.value = i.name; o2.textContent = label; craft.appendChild(o2); }
    });
    if (!sel.options.length) { const o = document.createElement("option"); o.textContent = "no interfaces found"; sel.appendChild(o); }
  } catch (e) {}
}

function setStatus(kind, text) {
  els.status.className = "status" + (kind ? " " + kind : "");
  els.status.querySelector(".status-text").textContent = text;
}

function resetBuffer() {
  state.packets = []; state.buffer = []; state.protoCounts = {}; state.rateWindow = [];
  els.body.innerHTML = ""; els.empty.hidden = false;
  $("#detail-content").hidden = true; $("#detail-empty").hidden = false;
}

async function toggleCapture() {
  if (state.running) {
    await fetch("/api/capture/stop", { method: "POST" });
    state.running = false;
    els.captureBtn.classList.remove("recording");
    els.captureLabel.textContent = "Start capture";
    setStatus("", "stopped");
  } else {
    await fetch("/api/capture/clear", { method: "POST" });
    resetBuffer();
    $("#source-tag").hidden = true;
    const body = { iface: $("#iface").value || null, bpf: $("#bpf").value || null, promisc: $("#promisc").checked };
    const r = await fetch("/api/capture/start", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const data = await r.json();
    if (!r.ok) { setStatus("error", "error"); els.empty.hidden = false; els.empty.querySelector("p").textContent = data.error || "Could not start capture."; return; }
    state.running = true;
    els.captureBtn.classList.add("recording");
    els.captureLabel.textContent = "Stop capture";
    setStatus("live", "capturing");
  }
}

function protoBadge(proto) {
  const span = document.createElement("span");
  span.className = "proto-badge";
  span.dataset.p = PROTO_COLOR[proto] ? proto : "other";
  span.textContent = proto;
  return span;
}

function noteFlag(ip) { if (ip && !(ip in flagByIp) && !pendingFlags.has(ip)) pendingFlags.add(ip); }
function noteName(ip) { if (ip && !(ip in hostByIp) && !pendingNames.has(ip)) pendingNames.add(ip); }
function cellLabel(ip) { return (state.resolveDns && hostByIp[ip]) ? hostByIp[ip] : (ip || "—"); }

function flagSpan(ip) {
  const s = document.createElement("span");
  s.className = "ip-flag"; s.dataset.ip = ip || "";
  const cc = flagByIp[ip];
  if (cc && cc !== "PRIVATE") s.textContent = flagEmoji(cc);
  return s;
}
function addrCell(ip) {
  const td = document.createElement("td");
  td.className = "c-addr"; td.dataset.ip = ip || "";
  const note = ip ? state.ipNotes[ip] : null;
  let title = ip || "";
  if (note) {
    if (note.description) title += " — " + note.description;
    if (note.tags && note.tags.length) title += " [" + note.tags.join(", ") + "]";
  }
  td.title = title;
  td.appendChild(flagSpan(ip));
  if (note && note.color) {
    const dot = document.createElement("span");
    dot.className = "ip-tag-dot"; dot.style.background = note.color;
    td.appendChild(dot);
  }
  const label = document.createElement("span");
  label.className = "addr-label"; label.dataset.ip = ip || "";
  label.textContent = cellLabel(ip);
  td.appendChild(label);
  noteFlag(ip);
  if (state.resolveDns) noteName(ip);
  return td;
}

function rowTagColor(pkt) {
  const s = state.ipNotes[pkt.src], d = state.ipNotes[pkt.dst];
  return (s && s.color) || (d && d.color) || null;
}

/* ---------- display filter engine ---------- */
const RESERVED = new Set(["and", "or", "not", "tcp", "udp", "icmp", "arp", "dns", "http", "https",
  "port", "sport", "dport", "src", "dst", "host", "domain", "flags", "proto", "threat", "len",
  "==", "=", "!=", ">", "<", ">=", "<=", "(", ")"]);

function tokenize(s) {
  const toks = [];
  const two = [">=", "<=", "!=", "=="];
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === " " || c === "\t") { i++; continue; }
    if (c === "(" || c === ")") { toks.push(c); i++; continue; }
    const pair = s.substr(i, 2);
    if (two.includes(pair)) { toks.push(pair); i += 2; continue; }
    if (c === ">" || c === "<" || c === "=") { toks.push(c); i++; continue; }
    if (c === "!") { toks.push("!"); i++; continue; }
    let j = i;
    while (j < s.length && !" \t()><=!".includes(s[j])) j++;
    toks.push(s.slice(i, j)); i = j;
  }
  return toks;
}
function cmp(op, a, b) {
  if (a == null) return false;
  switch (op) {
    case ">": return a > b; case "<": return a < b;
    case ">=": return a >= b; case "<=": return a <= b;
    case "!=": return a != b; default: return a == b;
  }
}
function isExprLike(str) {
  return tokenize(str).some(t => RESERVED.has(t.toLowerCase()));
}
function flagPred(val) {
  if (val.toLowerCase() === "none") return p => p.transport === "tcp" && (!p.flags || !p.flags.length);
  const V = val.toUpperCase();
  return p => (p.flags || []).some(f => f === V || f[0] === V);
}
function compileExpr(str) {
  const toks = tokenize(str);
  let pos = 0;
  const peek = () => toks[pos];
  const eat = () => toks[pos++];

  function parseOr() {
    let left = parseAnd();
    while (peek() && peek().toLowerCase() === "or") { eat(); const r = parseAnd(); const l = left; left = p => l(p) || r(p); }
    return left;
  }
  function parseAnd() {
    let left = parseNot();
    while (peek() && peek().toLowerCase() === "and") { eat(); const r = parseNot(); const l = left; left = p => l(p) && r(p); }
    return left;
  }
  function parseNot() {
    if (peek() && peek().toLowerCase() === "not") { eat(); const inner = parseNot(); return p => !inner(p); }
    return parsePrimary();
  }
  function parsePrimary() {
    if (peek() === "(") { eat(); const e = parseOr(); if (eat() !== ")") throw new Error("missing )"); return e; }
    return parseAtom();
  }
  function parseAtom() {
    const raw = eat();
    if (raw === undefined) throw new Error("unexpected end of filter");
    const tok = raw.toLowerCase();
    if (tok === "tcp" || tok === "udp" || tok === "icmp" || tok === "arp") return p => p.transport === tok;
    if (tok === "dns") return p => p.proto === "DNS";
    if (tok === "http") return p => p.proto === "HTTP";
    if (tok === "https") return p => p.proto === "HTTPS";
    if (tok === "threat") {
      let lvl = null;
      const nx = (peek() || "").toLowerCase();
      if (["high", "medium", "low"].includes(nx)) { lvl = nx; eat(); }
      return p => p.threat && (lvl ? p.threat.level === lvl : p.threat.level !== "none");
    }
    const OPS = ["==", "=", "!=", ">", "<", ">=", "<="];
    if (["port", "sport", "dport", "len", "src", "dst", "host", "domain", "flags", "proto"].includes(tok)) {
      if (tok === "flags") {
        const val = eat();
        if (val === undefined) throw new Error("expected a flag after 'flags'");
        return flagPred(val);
      }
      let op = "==";
      if (OPS.includes(peek())) op = eat();
      const val = eat();
      if (val === undefined) throw new Error("expected a value after '" + tok + "'");
      if (tok === "len") { const n = +val; return p => cmp(op, p.length, n); }
      if (tok === "sport") { const n = +val; return p => cmp(op, p.sport, n); }
      if (tok === "dport") { const n = +val; return p => cmp(op, p.dport, n); }
      if (tok === "port") {
        const n = +val;
        if (op === "!=") return p => p.sport !== n && p.dport !== n;
        return p => cmp(op, p.sport, n) || cmp(op, p.dport, n);
      }
      // string fields: only == / !=
      if (op !== "==" && op !== "=" && op !== "!=") throw new Error("use == or != with '" + tok + "'");
      const neq = op === "!=";
      const get = tok === "src" ? (p => p.src || "") : tok === "dst" ? (p => p.dst || "")
        : tok === "domain" ? (p => (p.domain || "").toLowerCase()) : tok === "proto" ? (p => (p.proto || "").toLowerCase()) : null;
      if (tok === "host") return neq ? (p => p.src !== val && p.dst !== val) : (p => p.src === val || p.dst === val);
      if (tok === "domain") {
        const needle = val.toLowerCase();
        return neq ? (p => !get(p).includes(needle)) : (p => get(p).includes(needle));
      }
      const target = tok === "proto" ? val.toLowerCase() : val;
      return neq ? (p => get(p) !== target) : (p => get(p) === target);
    }
    throw new Error("don't understand '" + raw + "'");
  }
  const pred = parseOr();
  if (pos < toks.length) throw new Error("unexpected '" + toks[pos] + "'");
  return pred;
}

function substringPred(str) {
  const q = str.toLowerCase();
  return p => (p.src || "").toLowerCase().includes(q) || (p.dst || "").toLowerCase().includes(q)
    || (p.proto || "").toLowerCase().includes(q) || String(p.sport || "").includes(q)
    || String(p.dport || "").includes(q) || (p.info || "").toLowerCase().includes(q)
    || (p.domain || "").toLowerCase().includes(q);
}

function updateDisplayFilter(str) {
  const input = $("#display-filter");
  input.classList.remove("valid", "invalid"); input.title = "";
  if (!str.trim()) { state.displayPredicate = () => true; rerenderTable(); return; }
  if (isExprLike(str)) {
    try {
      state.displayPredicate = compileExpr(str);
      input.classList.add("valid");
      rerenderTable();
    } catch (e) {
      input.classList.add("invalid"); input.title = "Invalid filter: " + e.message;
      // keep the previous predicate; don't re-filter on a broken expression
    }
  } else {
    state.displayPredicate = substringPred(str);
    input.classList.add("valid");
    rerenderTable();
  }
}

function visible(pkt) {
  if (state.flaggedOnly && (!pkt.threat || pkt.threat.level === "none")) return false;
  return state.displayPredicate(pkt);
}

function makeRow(pkt, isNew) {
  const tr = document.createElement("tr");
  const lvl = pkt.threat ? pkt.threat.level : "none";
  tr.className = "pkt-row" + (isNew ? " new-row" : "") + (lvl !== "none" ? " t-" + lvl : "");
  tr.dataset.n = pkt.number;

  const num = document.createElement("td"); num.className = "c-num"; num.textContent = pkt.number;
  const time = document.createElement("td"); time.className = "c-time"; time.textContent = etTime(pkt.epoch);
  const src = addrCell(pkt.src);
  const dst = addrCell(pkt.dst);
  const proto = document.createElement("td"); proto.className = "c-proto"; proto.appendChild(protoBadge(pkt.proto));
  const len = document.createElement("td"); len.className = "c-len"; len.textContent = pkt.length;
  const info = document.createElement("td"); info.className = "c-info"; info.title = pkt.info || "";
  info.textContent = pkt.info || "";
  if (lvl !== "none") { const d = document.createElement("span"); d.className = "tdot t-" + lvl; info.appendChild(d); }

  tr.append(num, time, src, dst, proto, len, info);
  tr.addEventListener("click", () => selectPacket(pkt.number, tr));
  const tagColor = rowTagColor(pkt);
  if (tagColor) {
    const mark = document.createElement("span");
    mark.className = "row-tag-mark"; mark.style.background = tagColor;
    tr.appendChild(mark);
  }
  return tr;
}

function flushBuffer() {
  if (!state.buffer.length || state.paused) return;
  const atBottom = els.scroll.scrollHeight - els.scroll.scrollTop - els.scroll.clientHeight < 60;
  const frag = document.createDocumentFragment();
  let added = 0;
  for (const pkt of state.buffer) if (visible(pkt)) { frag.appendChild(makeRow(pkt, true)); added++; }
  state.buffer = [];
  if (added) {
    els.empty.hidden = true;
    els.body.appendChild(frag);
    while (els.body.children.length > state.maxRows) els.body.removeChild(els.body.firstChild);
    if (atBottom) els.scroll.scrollTop = els.scroll.scrollHeight;
  }
}
setInterval(flushBuffer, 200);

function rerenderTable() {
  els.body.innerHTML = "";
  const frag = document.createDocumentFragment();
  const matched = state.packets.filter(visible);
  matched.slice(-state.maxRows).forEach(p => frag.appendChild(makeRow(p, false)));
  els.body.appendChild(frag);
  els.empty.hidden = matched.length > 0;
}

async function resolveFlags() {
  if (!pendingFlags.size) return;
  const batch = [...pendingFlags].slice(0, 100);
  batch.forEach(ip => pendingFlags.delete(ip));
  try {
    const r = await fetch("/api/geo-flags", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ips: batch }) });
    const data = await r.json();
    Object.entries(data.countries || {}).forEach(([ip, code]) => {
      flagByIp[ip] = code;
      if (code && code !== "PRIVATE") {
        const emoji = flagEmoji(code);
        $$(`.ip-flag[data-ip="${CSS.escape(ip)}"]`).forEach(el => { el.textContent = emoji; });
      }
    });
  } catch (e) {}
}
setInterval(resolveFlags, 1200);

async function resolveNames() {
  if (!state.resolveDns || !pendingNames.size) return;
  const batch = [...pendingNames].slice(0, 50);
  batch.forEach(ip => pendingNames.delete(ip));
  try {
    const r = await fetch("/api/resolve", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ips: batch }) });
    const data = await r.json();
    Object.entries(data.names || {}).forEach(([ip, host]) => {
      hostByIp[ip] = host;
      if (host && state.resolveDns) $$(`.addr-label[data-ip="${CSS.escape(ip)}"]`).forEach(el => { el.textContent = host; });
    });
  } catch (e) {}
}
setInterval(resolveNames, 1200);

function updateStats() {
  els.count.textContent = state.packets.length.toLocaleString();
  const now = Date.now();
  state.rateWindow = state.rateWindow.filter(t => now - t < 2000);
  els.rate.innerHTML = Math.round(state.rateWindow.length / 2) + "<em>/s</em>";
  const total = Object.values(state.protoCounts).reduce((a, b) => a + b, 0) || 1;
  els.protoBar.innerHTML = "";
  Object.entries(state.protoCounts).sort((a, b) => b[1] - a[1]).forEach(([p, c]) => {
    const s = document.createElement("span");
    s.style.width = (c / total * 100) + "%";
    s.style.background = PROTO_COLOR[p] || "#c0708a";
    s.title = `${p}: ${c}`;
    els.protoBar.appendChild(s);
  });
}
setInterval(updateStats, 500);

async function selectPacket(n, tr, source) {
  source = source || "capture";
  $$(".pkt-row.selected").forEach(r => r.classList.remove("selected"));
  if (tr) tr.classList.add("selected");
  state.selected = n;
  const url = source === "nc" ? "/api/nc/packet/" + n : "/api/packet/" + n;
  const r = await fetch(url);
  if (!r.ok) return;
  const d = await r.json();
  const pkt = (source === "nc" ? ncState.packets : state.packets).find(p => p.number === n);
  d.rowThreat = pkt ? pkt.threat : d.threat;
  state.selectedDetail = d;
  renderDetail(n, d, source);
}

function layerFields(detail, name) {
  const l = detail.layers.find(x => x.name === name);
  return l ? l.fields : null;
}

function renderDetail(n, d, source) {
  source = source || "capture";
  $("#detail-empty").hidden = true;
  $("#detail-content").hidden = false;
  $("#detail-title").textContent = "Packet #" + n;
  $("#detail-len").textContent = d.length + " bytes";

  const ip = layerFields(d, "IP") || layerFields(d, "IPv6");
  const src = ip ? ip.src : null, dst = ip ? ip.dst : null;
  const actions = $("#detail-actions"); actions.innerHTML = "";
  const send = document.createElement("button");
  send.className = "btn btn-primary"; send.textContent = "Send to Crafter";
  send.addEventListener("click", () => fillCrafterFromDetail(d));
  actions.appendChild(send);

  const replay = document.createElement("button");
  replay.className = "btn btn-ghost"; replay.textContent = "Replay";
  replay.title = "Re-transmit this exact packet on the wire";
  replay.addEventListener("click", async () => {
    replay.disabled = true; const orig = replay.textContent; replay.textContent = "Sending…";
    try {
      const url = source === "nc" ? "/api/nc/packet/" + n + "/replay" : "/api/packet/" + n + "/replay";
      const r = await fetch(url, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ count: 1 }),
      });
      const res = await r.json();
      replay.textContent = r.ok ? "Sent ✓" : "Failed";
      if (!r.ok) alert(res.error || "Replay failed.");
    } catch (e) { replay.textContent = "Failed"; alert(String(e)); }
    setTimeout(() => { replay.textContent = orig; replay.disabled = false; }, 1400);
  });
  actions.appendChild(replay);
  [src, dst].filter((v, i, a) => v && !isPrivateIp(v) && a.indexOf(v) === i).forEach(pubip => {
    const look = document.createElement("button");
    look.className = "btn btn-ghost"; look.textContent = "Look up " + pubip;
    look.addEventListener("click", () => { $("#intel-ip").value = pubip; activateTab("intel"); lookupIP(); });
    actions.appendChild(look);
    const ab = document.createElement("a");
    ab.className = "btn btn-ghost"; ab.href = "https://www.abuseipdb.com/check/" + encodeURIComponent(pubip);
    ab.target = "_blank"; ab.rel = "noopener"; ab.textContent = "AbuseIPDB ↗";
    actions.appendChild(ab);
  });

  const tp = $("#threat-panel");
  const th = d.rowThreat || d.threat || { level: "none", reasons: [] };
  if (th.level === "none" || !th.reasons.length) {
    tp.className = "threat-panel clean"; tp.textContent = "No heuristic flags on this packet.";
  } else {
    tp.className = "threat-panel";
    tp.innerHTML = `<div class="threat-head">Threat signals <span class="lvl t-${th.level}">${th.level}</span></div>`
      + `<ul class="threat-reasons">` + th.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join("") + `</ul>`;
  }

  const pl = $("#proc-line"); const proc = d.process;
  if (!proc) pl.hidden = true;
  else if (proc.available === false) { pl.hidden = false; pl.innerHTML = `<span class="k">Local process</span><span class="v dim">unavailable (${escapeHtml(proc.reason || "")})</span>`; }
  else if (proc.name) { pl.hidden = false; pl.innerHTML = `<span class="k">Local process</span><span class="v">${escapeHtml(proc.name)}${proc.pid ? " (pid " + proc.pid + ")" : ""}${proc.laddr ? " · " + escapeHtml(proc.laddr) : ""}</span>`; }
  else { pl.hidden = false; pl.innerHTML = `<span class="k">Local process</span><span class="v dim">${escapeHtml(proc.note || "no local match")}</span>`; }

  const tree = $("#layer-tree"); tree.innerHTML = "";
  d.layers.forEach((layer, i) => {
    const det = document.createElement("details"); det.className = "layer"; if (i < 3) det.open = true;
    const sum = document.createElement("summary"); sum.innerHTML = `<span class="lname">${escapeHtml(layer.name)}</span>`;
    det.appendChild(sum);
    const fields = document.createElement("div"); fields.className = "fields";
    Object.entries(layer.fields).forEach(([k, v]) => {
      const row = document.createElement("div"); row.className = "frow";
      row.innerHTML = `<span class="fk">${escapeHtml(k)}</span><span class="fv">${escapeHtml(String(v))}</span>`;
      fields.appendChild(row);
    });
    det.appendChild(fields); tree.appendChild(det);
  });

  const hex = $("#hex-view"); hex.innerHTML = "";
  d.hex.forEach(line => {
    const div = document.createElement("div"); div.className = "hex-line";
    div.innerHTML = `<span class="hex-off">${line.offset}</span><span class="hex-bytes">${line.hex}</span><span class="hex-ascii">${escapeHtml(line.ascii)}</span>`;
    hex.appendChild(div);
  });

  buildRules(d);
}

function buildRules(d) {
  const ip = layerFields(d, "IP") || layerFields(d, "IPv6");
  const tcp = layerFields(d, "TCP"), udp = layerFields(d, "UDP"), icmp = layerFields(d, "ICMP");
  const proto = tcp ? "tcp" : udp ? "udp" : icmp ? "icmp" : "ip";
  const src = ip ? ip.src : "any", dst = ip ? ip.dst : "any";
  const sport = tcp ? tcp.sport : udp ? udp.sport : "any";
  const dport = tcp ? tcp.dport : udp ? udp.dport : "any";
  const sid = 9000000 + Math.floor(Math.random() * 999999);
  let flagsOpt = "";
  if (tcp && tcp.flags) {
    const set = [...String(tcp.flags)].filter(c => "SAFRPU".includes(c)).join(",");
    if (set) flagsOpt = ` flags:${set};`;
  }
  $("#rule-suricata").textContent =
    `alert ${proto} ${src} ${sport} -> ${dst} ${dport} ` +
    `(msg:"NetworkCompanion ${proto.toUpperCase()} ${src}:${sport} -> ${dst}:${dport}";${flagsOpt} sid:${sid}; rev:1;)`;

  const parts = [];
  if (ip && src !== "any") parts.push(`src_ip="${src}"`);
  if (ip && dst !== "any") parts.push(`dest_ip="${dst}"`);
  if (dport !== "any") parts.push(`dest_port=${dport}`);
  if (proto !== "ip") parts.push(`transport=${proto}`);
  $("#rule-splunk").textContent =
    `index=* sourcetype=* ${parts.join(" ")}\n` +
    `| stats count min(_time) as first max(_time) as last by src_ip dest_ip dest_port transport\n` +
    `| eval first=strftime(first,"%F %T"), last=strftime(last,"%F %T")`;
}

function fillCrafterFromDetail(d) {
  const ip4 = layerFields(d, "IP"), ip6 = layerFields(d, "IPv6");
  setIpVer(ip6 && !ip4 ? "6" : "4");
  const ip = ip4 || ip6 || {};
  $("#ip-src").value = ip.src || "";
  $("#ip-dst").value = ip.dst || "";
  $("#ip-ttl").value = ip4 && ip4.ttl != null ? String(ip4.ttl).replace(/\D/g, "") : "";
  const tcp = layerFields(d, "TCP"), udp = layerFields(d, "UDP"), icmp = layerFields(d, "ICMP");
  if (tcp) {
    setTransport("tcp");
    $("#tcp-sport").value = tcp.sport ?? ""; $("#tcp-dport").value = tcp.dport ?? "";
    $("#tcp-seq").value = String(tcp.seq ?? "").replace(/\D/g, "");
    const present = new Set([...String(tcp.flags || "")]);
    setFlags(["S", "A", "F", "R", "P", "U"].filter(x => present.has(x)));
  } else if (udp) {
    setTransport("udp"); $("#udp-sport").value = udp.sport ?? ""; $("#udp-dport").value = udp.dport ?? "";
  } else if (icmp) {
    setTransport("icmp"); $("#icmp-type").value = String(icmp.type ?? "").replace(/\D/g, ""); $("#icmp-code").value = String(icmp.code ?? "").replace(/\D/g, "");
  } else setTransport("none");
  activateTab("craft");
  log("Loaded a packet into the crafter. Review the fields before sending.", "hl");
}

document.addEventListener("click", e => {
  const btn = e.target.closest("[data-copy]");
  if (!btn) return;
  navigator.clipboard.writeText($("#" + btn.dataset.copy).textContent).then(() => {
    const o = btn.textContent; btn.textContent = "Copied"; setTimeout(() => btn.textContent = o, 1200);
  });
});

function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onmessage = ev => {
    const pkt = JSON.parse(ev.data);
    if (pkt.channel === "nc") {
      ncState.packets.push(pkt);
      ncState.buffer.push(pkt);
      noteFlag(pkt.src); noteFlag(pkt.dst);
      return;
    }
    // Unbounded on purpose: nothing gets dropped from a running capture.
    state.packets.push(pkt);
    state.buffer.push(pkt);
    state.protoCounts[pkt.proto] = (state.protoCounts[pkt.proto] || 0) + 1;
    state.rateWindow.push(Date.now());
    noteFlag(pkt.src); noteFlag(pkt.dst);
    if (state.resolveDns) { noteName(pkt.src); noteName(pkt.dst); }
  };
  ws.onclose = () => setTimeout(connectWS, 1500);
}

/* ---------- capture controls ---------- */
els.captureBtn.addEventListener("click", toggleCapture);
$("#pause-btn").addEventListener("click", e => {
  state.paused = !state.paused;
  e.target.textContent = state.paused ? "Resume" : "Pause";
  e.target.classList.toggle("btn-primary", state.paused);
});
$("#flagged-btn").addEventListener("click", e => {
  state.flaggedOnly = !state.flaggedOnly;
  e.target.classList.toggle("active", state.flaggedOnly);
  rerenderTable();
});
$("#resolve-btn").addEventListener("click", e => {
  state.resolveDns = !state.resolveDns;
  e.target.classList.toggle("active", state.resolveDns);
  if (state.resolveDns) state.packets.forEach(p => { noteName(p.src); noteName(p.dst); });
  rerenderTable();
});
$("#clear-btn").addEventListener("click", async () => {
  await fetch("/api/capture/clear", { method: "POST" });
  resetBuffer(); $("#source-tag").hidden = true;
});
$("#export-btn").addEventListener("click", async () => {
  const r = await fetch("/api/export");
  if (!r.ok) { const d = await r.json(); alert(d.error); return; }
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = "network_companion_capture.pcap"; a.click();
  URL.revokeObjectURL(url);
});
$("#export-all-btn").addEventListener("click", async () => {
  const r = await fetch("/api/export/all");
  if (!r.ok) { const d = await r.json(); alert(d.error); return; }
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = "network_companion_capture_all_traffic.pcap"; a.click();
  URL.revokeObjectURL(url);
});
$("#display-filter").addEventListener("input", e => updateDisplayFilter(e.target.value));

/* capture-filter (BPF) validation */
let bpfTimer;
$("#bpf").addEventListener("input", () => { clearTimeout(bpfTimer); bpfTimer = setTimeout(validateBpf, 400); });
async function validateBpf() {
  const bpfInput = $("#bpf"), stateEl = $("#bpf-state");
  const val = bpfInput.value.trim();
  bpfInput.classList.remove("valid", "invalid"); stateEl.textContent = ""; stateEl.className = "filter-state"; bpfInput.title = "";
  if (!val) return;
  try {
    const r = await fetch("/api/validate-bpf", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ filter: val }) });
    const d = await r.json();
    if (d.status === "valid") { bpfInput.classList.add("valid"); stateEl.textContent = "valid"; stateEl.classList.add("valid"); }
    else if (d.status === "invalid") { bpfInput.classList.add("invalid"); stateEl.textContent = "invalid"; stateEl.classList.add("invalid"); bpfInput.title = d.error || "invalid filter"; }
  } catch (e) {}
}

/* Open PCAP */
$("#open-pcap-btn").addEventListener("click", () => $("#pcap-input").click());
$("#pcap-input").addEventListener("change", async e => {
  const file = e.target.files[0]; if (!file) return;
  const btn = $("#open-pcap-btn"); btn.disabled = true; btn.textContent = "Loading…";
  try {
    const fd = new FormData(); fd.append("file", file);
    const r = await fetch("/api/pcap/load", { method: "POST", body: fd });
    const d = await r.json();
    if (!r.ok) { alert(d.error || "Could not load capture."); return; }
    if (state.running) {
      state.running = false; els.captureBtn.classList.remove("recording");
      els.captureLabel.textContent = "Start capture"; setStatus("", "stopped");
    }
    state.packets = d.packets; state.buffer = []; state.protoCounts = {}; state.rateWindow = [];
    state.packets.forEach(p => {
      state.protoCounts[p.proto] = (state.protoCounts[p.proto] || 0) + 1;
      noteFlag(p.src); noteFlag(p.dst);
      if (state.resolveDns) { noteName(p.src); noteName(p.dst); }
    });
    rerenderTable();
    const tag = $("#source-tag"); tag.hidden = false;
    tag.textContent = "PCAP: " + d.name + ` (${d.count.toLocaleString()})`;
    $("#detail-content").hidden = true; $("#detail-empty").hidden = false;
  } catch (err) { alert(String(err)); }
  finally { btn.disabled = false; btn.textContent = "Open PCAP"; e.target.value = ""; }
});

/* ---------- resizable detail splitter ---------- */
(function () {
  const splitter = $("#detail-splitter"), detail = $("#detail");
  if (!splitter) return;
  let dragging = false;
  splitter.addEventListener("mousedown", e => { dragging = true; document.body.classList.add("dragging-split"); e.preventDefault(); });
  window.addEventListener("mousemove", e => {
    if (!dragging) return;
    // Resolved live, not cached: the detail pane moves between the Capture
    // and NC Traffic tabs (see activateTab), so its .capture-body changes.
    const body = detail.closest(".capture-body");
    if (!body) return;
    const rect = body.getBoundingClientRect();
    let w = Math.max(240, Math.min(rect.width - 300, rect.right - e.clientX));
    detail.style.flex = "0 0 " + w + "px";
  });
  window.addEventListener("mouseup", () => { if (dragging) { dragging = false; document.body.classList.remove("dragging-split"); } });
})();

/* ---------- resizable columns ---------- */
(function () {
  const wrap = $("#table-wrap");
  if (!wrap) return;
  $$(".col-resizer").forEach(rz => {
    rz.addEventListener("mousedown", e => {
      e.preventDefault(); e.stopPropagation();
      const varName = "--w-" + rz.dataset.col;
      const startX = e.clientX;
      const startW = parseInt(getComputedStyle(wrap).getPropertyValue(varName)) || 100;
      document.body.classList.add("col-resizing");
      function move(ev) {
        const w = Math.max(40, Math.min(600, startW + (ev.clientX - startX)));
        wrap.style.setProperty(varName, w + "px");
      }
      function up() { document.body.classList.remove("col-resizing"); window.removeEventListener("mousemove", move); window.removeEventListener("mouseup", up); }
      window.addEventListener("mousemove", move); window.addEventListener("mouseup", up);
    });
  });
})();

/* ============================================================
   NC TRAFFIC (packets Network Companion generated about itself)
   ============================================================ */
const ncState = { packets: [], buffer: [] };
const ncEls = { body: $("#nc-body"), empty: $("#nc-empty"), count: $("#nc-count") };

/* Show/hide toggle for the whole NC Traffic tab + its indicator. Doesn't
   stop classification or the buffer — purely a UI declutter switch for
   analysts who don't want to see it. Persisted so it stays put on reload. */
const NC_HIDE_KEY = "networkcompanion_hide_nc";
let ncHidden = localStorage.getItem(NC_HIDE_KEY) === "1";

function applyNcVisibility() {
  $("#nc-tab-btn").hidden = ncHidden;
  const btn = $("#nc-hide-btn");
  btn.classList.toggle("active", ncHidden);
  btn.textContent = ncHidden ? "Show NC Traffic" : "Hide NC Traffic";
  if (ncHidden && $("#panel-nc").classList.contains("active")) activateTab("capture");
  updateNcBadges();
}
$("#nc-hide-btn").addEventListener("click", () => {
  ncHidden = !ncHidden;
  localStorage.setItem(NC_HIDE_KEY, ncHidden ? "1" : "0");
  applyNcVisibility();
});

function updateNcBadges() {
  const n = ncState.packets.length;
  const badge = $("#nc-tab-badge");
  badge.textContent = n > 999 ? "999+" : n;
  badge.hidden = ncHidden || n === 0;
  const jump = $("#nc-jump");
  jump.hidden = ncHidden || n === 0;
  $("#nc-jump-count").textContent = n.toLocaleString();
  ncEls.count.textContent = n.toLocaleString();
}
applyNcVisibility();

function makeNcRow(pkt) {
  const tr = document.createElement("tr");
  tr.className = "pkt-row"; tr.dataset.n = pkt.number;
  const num = document.createElement("td"); num.className = "c-num"; num.textContent = pkt.number;
  const time = document.createElement("td"); time.className = "c-time"; time.textContent = etTime(pkt.epoch);
  const src = addrCell(pkt.src);
  const dst = addrCell(pkt.dst);
  const proto = document.createElement("td"); proto.className = "c-proto"; proto.appendChild(protoBadge(pkt.proto));
  const len = document.createElement("td"); len.className = "c-len"; len.textContent = pkt.length;
  const info = document.createElement("td"); info.className = "c-info"; info.title = pkt.reason || "";
  info.textContent = pkt.reason || "";
  tr.append(num, time, src, dst, proto, len, info);
  tr.addEventListener("click", () => selectPacket(pkt.number, tr, "nc"));
  return tr;
}

function flushNcBuffer() {
  if (!ncState.buffer.length) return;
  const frag = document.createDocumentFragment();
  for (const pkt of ncState.buffer) frag.appendChild(makeNcRow(pkt));
  ncState.buffer = [];
  ncEls.empty.hidden = true;
  ncEls.body.appendChild(frag);
  while (ncEls.body.children.length > state.maxRows) ncEls.body.removeChild(ncEls.body.firstChild);
  updateNcBadges();
}
setInterval(flushNcBuffer, 200);

function rerenderNcTable() {
  ncEls.body.innerHTML = "";
  const frag = document.createDocumentFragment();
  ncState.packets.slice(-state.maxRows).forEach(p => frag.appendChild(makeNcRow(p)));
  ncEls.body.appendChild(frag);
  ncEls.empty.hidden = ncState.packets.length > 0;
}

$("#nc-clear-btn").addEventListener("click", async () => {
  await fetch("/api/nc/clear", { method: "POST" });
  ncState.packets = []; ncState.buffer = [];
  ncEls.body.innerHTML = ""; ncEls.empty.hidden = false;
  updateNcBadges();
});
$("#nc-jump").addEventListener("click", () => activateTab("nc"));

async function deleteNcPacket(n, tr) {
  try { await fetch("/api/nc/packet/" + n, { method: "DELETE" }); } catch (e) {}
  ncState.packets = ncState.packets.filter(p => p.number !== n);
  if (tr) tr.remove();
  updateNcBadges();
}

/* ============================================================
   RIGHT-CLICK CONTEXT MENU + SAVED IP TAGS/COLORS
   ============================================================ */
let ctxMenuEl = null;
function closeCtxMenu() {
  if (ctxMenuEl) { ctxMenuEl.remove(); ctxMenuEl = null; }
  document.removeEventListener("mousedown", closeCtxMenuIfOutside, true);
}
function closeCtxMenuIfOutside(e) {
  if (ctxMenuEl && !ctxMenuEl.contains(e.target)) closeCtxMenu();
}
function openCtxMenu(x, y, items) {
  closeCtxMenu();
  const menu = document.createElement("div");
  menu.className = "ctx-menu";
  items.forEach(item => {
    if (item === "separator") { const sep = document.createElement("div"); sep.className = "ctx-sep"; menu.appendChild(sep); return; }
    const btn = document.createElement("button");
    btn.className = "ctx-item" + (item.danger ? " danger" : "");
    btn.textContent = item.label;
    btn.addEventListener("click", () => { closeCtxMenu(); item.action(); });
    menu.appendChild(btn);
  });
  document.body.appendChild(menu);
  const rect = menu.getBoundingClientRect();
  menu.style.left = Math.min(x, window.innerWidth - rect.width - 8) + "px";
  menu.style.top = Math.min(y, window.innerHeight - rect.height - 8) + "px";
  ctxMenuEl = menu;
  setTimeout(() => document.addEventListener("mousedown", closeCtxMenuIfOutside, true), 0);
}

document.addEventListener("contextmenu", e => {
  const tr = e.target.closest(".pkt-row");
  if (!tr) return;
  const inCapture = els.body.contains(tr);
  const inNc = ncEls.body.contains(tr);
  if (!inCapture && !inNc) return;
  e.preventDefault();
  const cell = e.target.closest(".c-addr");
  const ip = cell ? cell.dataset.ip : null;
  const n = +tr.dataset.n;
  const items = [];
  if (ip) {
    const hasNote = !!state.ipNotes[ip];
    items.push({ label: `Tag / color ${ip}…`, action: () => openIpNoteEditor(ip, e.clientX, e.clientY) });
    if (hasNote) items.push({ label: `Clear tag on ${ip}`, action: () => clearIpNote(ip) });
    items.push({ label: `Copy ${ip}`, action: () => navigator.clipboard.writeText(ip) });
    items.push({ label: `Look up ${ip} in IP Intel`, action: () => { $("#intel-ip").value = ip; activateTab("intel"); lookupIP(); } });
  }
  if (inNc) {
    if (items.length) items.push("separator");
    items.push({ label: "Delete packet", danger: true, action: () => deleteNcPacket(n, tr) });
  }
  if (!items.length) return;
  openCtxMenu(e.clientX, e.clientY, items);
});

const IP_TAG_PALETTE = ["#f0455e", "#ff8a3d", "#f5b544", "#35c77e", "#3dd6d0", "#5b9dff", "#a78bfa", "#8b97ad"];

function openIpNoteEditor(ip, x, y) {
  closeCtxMenu();
  const existing = state.ipNotes[ip] || {};
  let chosenColor = existing.color || "";
  const box = document.createElement("div");
  box.className = "ip-note-editor";
  box.innerHTML = `
    <div class="ine-head">Tag ${escapeHtml(ip)}</div>
    <div class="ine-colors">
      ${IP_TAG_PALETTE.map(c => `<button type="button" class="ine-swatch${existing.color === c ? " active" : ""}" style="background:${c}" data-color="${c}"></button>`).join("")}
      <button type="button" class="ine-swatch ine-none" data-color="" title="No color">✕</button>
    </div>
    <label class="ine-label">Tags<input id="ine-tags" type="text" placeholder="comma, separated, tags" value="${escapeHtml((existing.tags || []).join(", "))}" /></label>
    <label class="ine-label">Description<textarea id="ine-desc" rows="2" placeholder="Notes about this IP">${escapeHtml(existing.description || "")}</textarea></label>
    <div class="ine-actions">
      <button class="btn btn-ghost" id="ine-cancel">Cancel</button>
      <button class="btn btn-ghost" id="ine-delete">Delete</button>
      <button class="btn btn-primary" id="ine-save">Save</button>
    </div>`;
  document.body.appendChild(box);
  $$(".ine-swatch", box).forEach(sw => sw.addEventListener("click", () => {
    $$(".ine-swatch", box).forEach(s => s.classList.remove("active"));
    sw.classList.add("active");
    chosenColor = sw.dataset.color;
  }));
  const rect = box.getBoundingClientRect();
  box.style.left = Math.min(x, window.innerWidth - rect.width - 12) + "px";
  box.style.top = Math.min(y, window.innerHeight - rect.height - 12) + "px";

  function close() { box.remove(); document.removeEventListener("mousedown", onOutside, true); }
  function onOutside(e) { if (!box.contains(e.target)) close(); }
  setTimeout(() => document.addEventListener("mousedown", onOutside, true), 0);

  $("#ine-cancel", box).addEventListener("click", close);
  $("#ine-delete", box).addEventListener("click", async () => { await clearIpNote(ip); close(); });
  $("#ine-save", box).addEventListener("click", async () => {
    const tags = $("#ine-tags", box).value.split(",").map(t => t.trim()).filter(Boolean);
    const description = $("#ine-desc", box).value.trim();
    await saveIpNote(ip, chosenColor, tags, description);
    close();
  });
}

async function saveIpNote(ip, color, tags, description) {
  try {
    const r = await fetch("/api/ip-notes/" + encodeURIComponent(ip), {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ color, tags, description }),
    });
    const d = await r.json();
    if (r.ok) { state.ipNotes[ip] = d.note; rerenderTable(); rerenderNcTable(); renderSavedIps(); }
  } catch (e) {}
}

async function clearIpNote(ip) {
  try { await fetch("/api/ip-notes/" + encodeURIComponent(ip), { method: "DELETE" }); } catch (e) {}
  delete state.ipNotes[ip];
  rerenderTable(); rerenderNcTable(); renderSavedIps();
}

function renderSavedIps() {
  const body = $("#saved-ips-body"), table = $("#saved-ips-table"), empty = $("#saved-ips-empty");
  if (!body) return;
  const entries = Object.entries(state.ipNotes);
  table.hidden = entries.length === 0;
  empty.hidden = entries.length > 0;
  body.innerHTML = "";
  entries.sort((a, b) => a[0].localeCompare(b[0])).forEach(([ip, note]) => {
    const tr = document.createElement("tr");
    const colorTd = document.createElement("td");
    if (note.color) { const dot = document.createElement("span"); dot.className = "ip-tag-dot"; dot.style.background = note.color; colorTd.appendChild(dot); }
    const ipTd = document.createElement("td"); ipTd.textContent = ip;
    const tagsTd = document.createElement("td");
    (note.tags || []).forEach(t => { const s = document.createElement("span"); s.className = "cat"; s.textContent = t; tagsTd.appendChild(s); });
    const descTd = document.createElement("td"); descTd.textContent = note.description || "";
    const actionsTd = document.createElement("td");
    const editBtn = document.createElement("button"); editBtn.className = "btn btn-ghost"; editBtn.textContent = "Edit";
    editBtn.addEventListener("click", e => openIpNoteEditor(ip, e.clientX, e.clientY));
    const delBtn = document.createElement("button"); delBtn.className = "btn btn-ghost"; delBtn.textContent = "Delete";
    delBtn.addEventListener("click", () => clearIpNote(ip));
    actionsTd.append(editBtn, delBtn);
    tr.append(colorTd, ipTd, tagsTd, descTd, actionsTd);
    body.appendChild(tr);
  });
}

async function loadIpNotes() {
  try {
    const r = await fetch("/api/ip-notes");
    const d = await r.json();
    state.ipNotes = d.notes || {};
  } catch (e) {}
}

/* ============================================================
   CRAFTER
   ============================================================ */
let ipVer = "4", transportKind = "tcp", payloadMode = "text";

function setIpVer(v) {
  ipVer = v;
  $$("[data-ipver]").forEach(x => x.classList.toggle("active", x.dataset.ipver === v));
  $("#ttl-wrap").style.visibility = v === "4" ? "visible" : "hidden";
}
$$("[data-ipver]").forEach(b => b.addEventListener("click", () => setIpVer(b.dataset.ipver)));

function setTransport(kind) {
  transportKind = kind;
  $$("#transport-seg .seg-btn").forEach(x => x.classList.toggle("active", x.dataset.transport === kind));
  $("#tf-tcp").hidden = kind !== "tcp"; $("#tf-udp").hidden = kind !== "udp"; $("#tf-icmp").hidden = kind !== "icmp";
}
$$("#transport-seg .seg-btn").forEach(b => b.addEventListener("click", () => setTransport(b.dataset.transport)));

$$("#payload-seg .seg-btn").forEach(b => b.addEventListener("click", () => {
  $$("#payload-seg .seg-btn").forEach(x => x.classList.remove("active"));
  b.classList.add("active"); payloadMode = b.dataset.payload;
  $("#payload").placeholder = payloadMode === "hex" ? "deadbeef… (hex bytes)" : "Optional payload bytes";
}));

function setFlags(list) { $$("#tf-tcp .flag input").forEach(i => i.checked = list.includes(i.value)); }

function buildSpec() {
  const spec = {};
  if ($("#blk-ether").open) spec.ether = { src: $("#eth-src").value.trim(), dst: $("#eth-dst").value.trim() };
  const dst = $("#ip-dst").value.trim();
  if (ipVer === "4") spec.ip = { src: $("#ip-src").value.trim(), dst, ttl: $("#ip-ttl").value };
  else spec.ipv6 = { src: $("#ip-src").value.trim(), dst };
  if (transportKind === "tcp") {
    const flags = $$("#tf-tcp .flag input:checked").map(i => i.value).join("");
    spec.transport = { kind: "tcp", sport: $("#tcp-sport").value, dport: $("#tcp-dport").value, seq: $("#tcp-seq").value, flags };
  } else if (transportKind === "udp") {
    spec.transport = { kind: "udp", sport: $("#udp-sport").value, dport: $("#udp-dport").value };
  } else if (transportKind === "icmp") {
    spec.transport = { kind: "icmp", icmp_type: $("#icmp-type").value, icmp_code: $("#icmp-code").value };
  }
  const payload = $("#payload").value;
  if (payload.trim()) { spec.payload = payload.trim(); spec.payload_is_hex = payloadMode === "hex"; }
  spec.count = $("#send-count").value; spec.interval = $("#send-interval").value;
  spec.iface = $("#craft-iface").value || null;
  return spec;
}

const craftLog = $("#craft-log");
function log(msg, cls) {
  const t = new Date().toLocaleTimeString();
  craftLog.innerHTML = `<span class="${cls || ""}">[${t}] ${escapeHtml(msg)}</span>\n` + craftLog.innerHTML;
}

$("#preview-btn").addEventListener("click", async () => {
  const r = await fetch("/api/craft/preview", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ spec: buildSpec() }) });
  const d = await r.json();
  if (!r.ok) { log(d.error, "err"); return; }
  craftLog.innerHTML = `<span class="hl">${escapeHtml(d.summary)}</span>\n${d.layer} · ${d.length} bytes\n${d.note ? escapeHtml(d.note) + "\n" : ""}\n${escapeHtml(d.show)}\n\n` + craftLog.innerHTML;
});
$("#send-btn").addEventListener("click", async () => {
  const btn = $("#send-btn"); btn.disabled = true; btn.textContent = "Sending…";
  try {
    const r = await fetch("/api/craft/send", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ spec: buildSpec() }) });
    const d = await r.json();
    if (!r.ok) log(d.error, "err");
    else { log(`Sent ${d.sent} × ${d.summary} [${d.layer}, ${d.length}B] in ${d.elapsed}s`, "ok"); if (d.note) log(d.note, "hl"); }
  } catch (e) { log(String(e), "err"); }
  btn.disabled = false; btn.textContent = "Send packet";
});

const PRESETS = {
  syn: () => { setTransport("tcp"); $("#ip-dst").value = ""; $("#tcp-dport").value = 80; setFlags(["S"]); log("Loaded preset: TCP SYN to port 80", "hl"); },
  ping: () => { setTransport("icmp"); $("#icmp-type").value = 8; $("#icmp-code").value = 0; log("Loaded preset: ICMP echo request", "hl"); },
  dns: () => { setTransport("udp"); $("#udp-dport").value = 53; $("#ip-dst").value = "8.8.8.8"; log("Loaded preset: UDP to DNS resolver 8.8.8.8:53", "hl"); },
  udp: () => { setTransport("udp"); $("#udp-dport").value = 0; log("Loaded preset: UDP datagram", "hl"); },
  clear: () => {
    ["eth-src", "eth-dst", "ip-src", "ip-dst", "ip-ttl", "tcp-sport", "tcp-dport", "tcp-seq", "udp-sport", "udp-dport", "icmp-type", "icmp-code", "payload"].forEach(id => $("#" + id).value = "");
    $("#send-count").value = 1; $("#send-interval").value = 0; log("Form reset", "hl");
  },
};
$$("[data-preset]").forEach(b => b.addEventListener("click", () => PRESETS[b.dataset.preset]()));

/* ---------- filter presets (apply to the display filter) ---------- */
const FILTER_GROUPS = [
  {
    group: "Basic protocols", items: [
      ["TCP", "tcp"], ["UDP", "udp"], ["ICMP", "icmp"], ["DNS", "dns"], ["ARP", "arp"],
      ["HTTP (cleartext)", "http or port 80"], ["HTTPS", "https or port 443"],
    ]
  },
  {
    group: "Threat hunting", items: [
      ["All flagged (heuristics)", "threat"],
      ["High severity only", "threat high"],
      ["Scan flag patterns", "flags none or (flags F and flags P and flags U) or (flags F and not flags A and not flags S) or (flags S and not flags A and not flags R)"],
      ["Known C2 / backdoor ports", "port 4444 or port 4445 or port 31337 or port 12345 or port 12346 or port 27374 or port 1337 or port 5554 or port 3127 or port 65000 or port 54321 or port 9999"],
      ["Tor / SOCKS proxy ports", "port 9001 or port 9050 or port 9150 or port 1080"],
      ["Cleartext credentials", "port 21 or port 23 or port 25 or port 110 or port 143 or port 512 or port 513 or port 514"],
      ["RDP / SMB / NetBIOS (lateral movement)", "port 3389 or port 445 or port 139 or port 137"],
      ["Possible DNS tunneling", "dns and (threat or len > 90)"],
      ["Possible ICMP tunneling", "icmp and len > 100"],
      ["Large transfers (possible exfil)", "len > 1400"],
      ["VNC / remote desktop exposure", "port 5900 or port 5901 or port 5800 or port 3389"],
      ["Database ports exposed", "port 3306 or port 5432 or port 1433 or port 6379 or port 27017 or port 9200"],
    ]
  },
];
const FILTER_PRESETS = {};
FILTER_GROUPS.forEach(g => g.items.forEach(([label, expr]) => { FILTER_PRESETS[label] = expr; }));

(function () {
  const sel = $("#filter-preset");
  const first = document.createElement("option");
  first.value = ""; first.textContent = "Threat presets…";
  sel.appendChild(first);
  FILTER_GROUPS.forEach(g => {
    const og = document.createElement("optgroup"); og.label = g.group;
    g.items.forEach(([label]) => {
      const o = document.createElement("option");
      o.value = label; o.textContent = label;
      og.appendChild(o);
    });
    sel.appendChild(og);
  });
  sel.addEventListener("change", () => {
    const expr = FILTER_PRESETS[sel.value] || "";
    $("#display-filter").value = expr;
    updateDisplayFilter(expr);
  });
})();

/* ============================================================
   TRANSFER
   ============================================================ */
const xferLog = $("#xfer-log");
function xlog(msg, cls) {
  const t = new Date().toLocaleTimeString();
  xferLog.innerHTML = `<span class="${cls || ""}">[${t}] ${escapeHtml(msg)}</span>\n` + xferLog.innerHTML;
}
$("#tcp-send-file").addEventListener("click", async () => {
  const host = $("#tcp-host").value.trim(), port = $("#tcp-port").value.trim(), f = $("#tcp-file").files[0];
  if (!host || !port || !f) { xlog("Host, port, and a file are required.", "err"); return; }
  const btn = $("#tcp-send-file"); btn.disabled = true; btn.textContent = "Sending…";
  try {
    const fd = new FormData(); fd.append("host", host); fd.append("port", port); fd.append("file", f);
    const r = await fetch("/api/transfer/tcp", { method: "POST", body: fd });
    const d = await r.json();
    if (!r.ok) xlog(d.error, "err"); else xlog(`Sent ${d.name} (${d.sent} bytes) to ${d.host}:${d.port} over TCP`, "ok");
  } catch (e) { xlog(String(e), "err"); }
  btn.disabled = false; btn.textContent = "Send file";
});
$("#ftp-send-file").addEventListener("click", async () => {
  const host = $("#ftp-host").value.trim(), f = $("#ftp-file").files[0];
  if (!host || !f) { xlog("FTP host and a file are required.", "err"); return; }
  const btn = $("#ftp-send-file"); btn.disabled = true; btn.textContent = "Uploading…";
  try {
    const fd = new FormData();
    fd.append("host", host); fd.append("port", $("#ftp-port").value.trim() || "21");
    fd.append("user", $("#ftp-user").value); fd.append("password", $("#ftp-pass").value);
    fd.append("remote", $("#ftp-remote").value.trim()); fd.append("file", f);
    const r = await fetch("/api/transfer/ftp", { method: "POST", body: fd });
    const d = await r.json();
    if (!r.ok) xlog(d.error, "err"); else xlog(`Uploaded ${d.name} (${d.sent} bytes) to ${d.host} as ${d.remote}`, "ok");
  } catch (e) { xlog(String(e), "err"); }
  btn.disabled = false; btn.textContent = "Upload file";
});

/* ============================================================
   PORT SCAN
   ============================================================ */
let scanResults = [];
function renderScan() {
  const showClosed = $("#scan-show-closed").checked;
  const body = $("#scan-body"); body.innerHTML = "";
  const rows = scanResults.filter(r => showClosed || r.state === "open");
  $("#scan-table").hidden = rows.length === 0;
  $("#scan-empty").hidden = rows.length > 0 || scanResults.length > 0;
  if (!rows.length && scanResults.length) {
    $("#scan-empty").hidden = false;
    $("#scan-empty").innerHTML = "<p>No open ports found. Tick “show closed / filtered” to see everything.</p>";
  }
  const frag = document.createDocumentFragment();
  rows.forEach(r => {
    const tr = document.createElement("tr"); tr.className = "st-" + r.state;
    tr.innerHTML = `<td>${r.port}</td><td>${r.state}</td><td>${escapeHtml(r.service || "")}</td><td>${escapeHtml(r.banner || "")}</td>`;
    frag.appendChild(tr);
  });
  body.appendChild(frag);
}
$("#scan-show-closed").addEventListener("change", renderScan);

$("#scan-btn").addEventListener("click", async () => {
  const host = $("#scan-host").value.trim();
  if (!host) { alert("Enter a target host."); return; }
  const btn = $("#scan-btn"); btn.disabled = true; btn.textContent = "Scanning…";
  $("#scan-summary").hidden = false; $("#scan-summary").innerHTML = `Scanning <b>${escapeHtml(host)}</b>…`;
  $("#scan-empty").hidden = true; $("#scan-table").hidden = true;
  try {
    const r = await fetch("/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ host, ports: $("#scan-ports").value.trim() || "top100", scan_type: $("#scan-type").value, banner: $("#scan-banner").checked }),
    });
    const d = await r.json();
    if (!r.ok) { $("#scan-summary").innerHTML = `<span style="color:var(--red)">${escapeHtml(d.error)}</span>`; scanResults = []; return; }
    scanResults = d.results;
    $("#scan-summary").innerHTML = `<b>${d.host}</b> · ${d.scan_type} scan · ${d.scanned} ports in ${d.elapsed}s · <b>${d.open}</b> open`;
    renderScan();
  } catch (e) { $("#scan-summary").innerHTML = `<span style="color:var(--red)">${escapeHtml(String(e))}</span>`; }
  finally { btn.disabled = false; btn.textContent = "Scan"; }
});

/* ---------- send data over TCP/TLS ---------- */
let sdPayloadMode = "text";
let sdKeylog = null;
$$("#sd-payload-seg .seg-btn").forEach(b => b.addEventListener("click", () => {
  $$("#sd-payload-seg .seg-btn").forEach(x => x.classList.remove("active"));
  b.classList.add("active"); sdPayloadMode = b.dataset.sdpayload;
}));
$("#sd-send").addEventListener("click", async () => {
  const host = $("#sd-host").value.trim(), port = $("#sd-port").value.trim();
  if (!host || !port) { xlog("Host and port are required.", "err"); return; }
  const btn = $("#sd-send"); btn.disabled = true; btn.textContent = "Sending…";
  $("#sd-keylog").hidden = true; $("#sd-keylog-note").hidden = true; sdKeylog = null;
  try {
    const r = await fetch("/api/transfer/send", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        host, port: +port, payload: $("#sd-payload").value,
        payload_is_hex: sdPayloadMode === "hex", tls: $("#sd-proto").value === "tls",
        read_response: $("#sd-read").checked,
      }),
    });
    const d = await r.json();
    if (!r.ok) { xlog(d.error, "err"); return; }
    let line = `Sent ${d.sent} bytes to ${d.host}:${d.port} over ${d.mode.toUpperCase()}`;
    if (d.tls) line += ` (${d.tls.version}, ${d.tls.cipher})`;
    line += ` · received ${d.received} bytes`;
    xlog(line, "ok");
    if (d.received) xlog("Response: " + d.response_preview, "");
    if (d.keylog) {
      sdKeylog = d.keylog;
      $("#sd-keylog").hidden = false;
      $("#sd-keylog-note").hidden = false;
      xlog("TLS key log captured for this connection, use “Download TLS key log” to decrypt a capture of it in Wireshark.", "hl");
    }
  } catch (e) { xlog(String(e), "err"); }
  finally { btn.disabled = false; btn.textContent = "Send"; }
});
$("#sd-keylog").addEventListener("click", () => {
  if (!sdKeylog) return;
  const blob = new Blob([sdKeylog], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "sslkeylog.log"; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
});

/* ============================================================
   IP INTEL
   ============================================================ */
let map = null, mapMarker = null;
const ABUSE_KEY = "networkcompanion_abuseipdb_key";

$("#intel-settings-btn").addEventListener("click", () => { const p = $("#key-panel"); p.hidden = !p.hidden; $("#abuse-key").value = localStorage.getItem(ABUSE_KEY) || ""; });
$("#save-key-btn").addEventListener("click", () => { localStorage.setItem(ABUSE_KEY, $("#abuse-key").value.trim()); $("#key-panel").hidden = true; });

async function lookupIP() {
  const ip = $("#intel-ip").value.trim(); if (!ip) return;
  const btn = $("#intel-btn"); btn.disabled = true; btn.textContent = "…";
  try {
    const r = await fetch("/api/intel", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip, api_key: localStorage.getItem(ABUSE_KEY) || null }) });
    const d = await r.json();
    if (!r.ok) { showIntelError(d.error); return; }
    renderIntel(d);
  } catch (e) { showIntelError(String(e)); }
  finally { btn.disabled = false; btn.textContent = "Look up"; }
}
function showIntelError(msg) { $("#intel-empty").hidden = false; $("#intel-results").hidden = true; $("#intel-empty").innerHTML = `<div class="notice warn">${escapeHtml(msg)}</div>`; }
function kv(k, v, cls) { return `<div class="kv"><span class="k">${k}</span><span class="v ${cls || ""}">${escapeHtml(String(v ?? "—"))}</span></div>`; }
function boolTag(v) { if (v === true) return `<span class="badge-yes">yes</span>`; if (v === false) return `<span class="badge-no">no</span>`; return "—"; }

function renderIntel(d) {
  $("#intel-empty").hidden = true; $("#intel-results").hidden = false;
  const geo = d.geo || {};
  $("#loc-flag").textContent = geo.ok ? flagEmoji(geo.countryCode) : (d.private ? "🏠" : "🏳️");
  if (geo.ok) {
    $("#loc-body").innerHTML =
      kv("IP", d.ip) + kv("Country", `${geo.country || "—"}${geo.countryCode ? " (" + geo.countryCode + ")" : ""}`) +
      kv("Region", geo.region) + kv("City", geo.city) + kv("ISP", geo.isp) + kv("Organisation", geo.org) +
      kv("ASN", geo.asn) + kv("Reverse DNS", geo.reverse || "—") +
      kv("Coordinates", (geo.lat != null ? `${geo.lat}, ${geo.lon}` : "—")) +
      `<div class="kv"><span class="k">Flags</span><span class="v">hosting ${boolTag(geo.hosting)} · proxy/vpn ${boolTag(geo.proxy)} · mobile ${boolTag(geo.mobile)}</span></div>`;
  } else {
    $("#loc-body").innerHTML = kv("IP", d.ip) + `<div class="notice info">${escapeHtml(geo.error || "No location data.")}</div>`;
  }
  renderThreat(d.abuse || {}, d.ip, d.private);
  renderMap(geo);
}

function renderThreat(abuse, ip, isPriv) {
  const scoreEl = $("#gauge-score"), fill = $("#gauge-fill"), meta = $("#threat-meta");
  const C = 314;
  const link = (!isPriv && ip) ? `<a class="abuse-link" href="https://www.abuseipdb.com/check/${encodeURIComponent(ip)}" target="_blank" rel="noopener">View full report on AbuseIPDB ↗</a>` : "";
  if (!abuse.ok) {
    scoreEl.textContent = "–"; fill.style.strokeDashoffset = C; fill.style.stroke = "var(--surface-3)";
    let m = `<div class="notice info">${escapeHtml(abuse.error || "No abuse score.")}</div>`;
    if (abuse.configured === false) m += `<div class="notice info">Add a key with “Key” for an inline score, or open the report below.</div>`;
    meta.innerHTML = m + link;
    return;
  }
  const score = abuse.score || 0;
  scoreEl.textContent = score;
  fill.style.strokeDashoffset = C - (C * score / 100);
  const color = score >= 75 ? "var(--red)" : score >= 40 ? "var(--amber)" : score >= 15 ? "#f5d144" : "var(--green)";
  fill.style.stroke = color; scoreEl.style.color = color;
  let cats = "";
  if (abuse.categories && abuse.categories.length) {
    cats = `<div class="kv"><span class="k">Reported for</span><span class="v"><div class="cats">` + abuse.categories.map(c => `<span class="cat">${escapeHtml(c)}</span>`).join("") + `</div></span></div>`;
  }
  meta.innerHTML = kv("Total reports", abuse.totalReports) + kv("Distinct sources", abuse.distinctUsers) +
    kv("Last reported", abuse.lastReported ? new Date(abuse.lastReported).toLocaleString() : "never") +
    kv("Usage type", abuse.usageType || "—") + cats + link;
}

function renderMap(geo) {
  const card = $(".map-card");
  if (typeof L === "undefined" || !geo.ok || geo.lat == null) { card.style.display = "none"; return; }
  card.style.display = "block";
  if (!map) {
    map = L.map("map", { attributionControl: false, zoomControl: true });
    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", { subdomains: "abcd", maxZoom: 12 }).addTo(map);
  }
  map.setView([geo.lat, geo.lon], 6);
  if (mapMarker) map.removeLayer(mapMarker);
  mapMarker = L.circleMarker([geo.lat, geo.lon], { radius: 8, color: "#3dd6d0", fillColor: "#3dd6d0", fillOpacity: .5, weight: 2 }).addTo(map).bindPopup(`${geo.city || ""} ${geo.country || ""}`.trim());
  setTimeout(() => map.invalidateSize(), 60);
}

$("#intel-btn").addEventListener("click", lookupIP);
$("#intel-ip").addEventListener("keydown", e => { if (e.key === "Enter") lookupIP(); });

/* ---------- global endpoint map ---------- */
let gmapInstance = null, gmapDots = [];

function uniqueCaptureIps() {
  const set = new Set();
  state.packets.forEach(p => { if (p.src) set.add(p.src); if (p.dst) set.add(p.dst); });
  return [...set];
}

async function plotGlobalMap() {
  const btn = $("#gmap-refresh"), sub = $("#gmap-sub");
  if (typeof L === "undefined") { sub.textContent = "Map library unavailable (offline?)."; return; }
  const ips = uniqueCaptureIps();
  if (!ips.length) { sub.textContent = "No packets yet. Start a capture or open a PCAP first."; return; }
  btn.disabled = true;
  const label = btn.textContent; btn.textContent = "Plotting…";
  try {
    const r = await fetch("/api/geo-points", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ips: ips.slice(0, 300) }),
    });
    const data = await r.json();
    const points = data.points || [];
    if (!gmapInstance) {
      gmapInstance = L.map("gmap", { attributionControl: false, zoomControl: true, worldCopyJump: true }).setView([20, 0], 2);
      L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", { subdomains: "abcd", maxZoom: 12 }).addTo(gmapInstance);
    }
    gmapDots.forEach(m => gmapInstance.removeLayer(m));
    gmapDots = points.map(pt => {
      const dot = L.circleMarker([pt.lat, pt.lon], {
        radius: 5, weight: 1, color: "#3dd6d0", fillColor: "#3dd6d0", fillOpacity: .85, className: "gmap-dot",
      }).addTo(gmapInstance);
      const tip = `${pt.ip}${pt.city ? " · " + pt.city : ""}${pt.country ? ", " + pt.country : ""}`;
      dot.bindTooltip(tip, { className: "gmap-tip", direction: "top", offset: [0, -4] });
      return dot;
    });
    sub.textContent = points.length
      ? `${points.length} public ${points.length === 1 ? "IP" : "IPs"} plotted, hover a dot for details (${ips.length} endpoint${ips.length === 1 ? "" : "s"} seen total).`
      : `No public IPs to plot yet (${ips.length} local/private endpoint${ips.length === 1 ? "" : "s"} seen).`;
    setTimeout(() => gmapInstance.invalidateSize(), 60);
  } catch (e) {
    sub.textContent = "Could not plot the map: " + e;
  } finally {
    btn.disabled = false; btn.textContent = label;
  }
}
$("#gmap-refresh").addEventListener("click", plotGlobalMap);

/* ---------- init ---------- */
loadInterfaces();
loadIpNotes();
connectWS();
fetch("/api/capture/status").then(r => r.json()).then(s => {
  if (s.running) { state.running = true; els.captureBtn.classList.add("recording"); els.captureLabel.textContent = "Stop capture"; setStatus("live", "capturing"); }
}).catch(() => {});
