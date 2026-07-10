/* Local network discovery tab: ARP-sweeps the local subnet and lists hosts
   with a best-effort vendor (MAC OUI) and device-type guess. Device
   inventory for a network you operate, vendors not identities.
   Relies on globals from app.js/stats.js: $, $$, escapeHtml,
   applyCaptureFilter, activateTab, lookupIP. */
(function () {
  const ifaceIp = {};

  async function loadNetIfaces() {
    const sel = $("#net-iface");
    if (!sel) return;
    try {
      const r = await fetch("/api/interfaces");
      const data = await r.json();
      sel.innerHTML = "";
      (data.interfaces || []).forEach(i => {
        ifaceIp[i.name] = i.ip || "";
        const o = document.createElement("option");
        o.value = i.name;
        o.textContent = i.name + (i.ip ? " · " + i.ip : "");
        sel.appendChild(o);
      });
      if (!sel.options.length) { const o = document.createElement("option"); o.textContent = "no interfaces found"; sel.appendChild(o); }
      autoCidr();
    } catch (e) {}
  }

  function autoCidr() {
    const cidr = $("#net-cidr"), sel = $("#net-iface");
    if (!cidr || !sel || cidr.value.trim()) return;
    const ip = ifaceIp[sel.value];
    if (ip && /^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
      cidr.placeholder = ip.replace(/\.\d+$/, ".0") + "/24 (auto)";
    }
  }

  const deviceClass = dev => {
    const d = (dev || "").toLowerCase();
    if (d.includes("playstation")) return "dev-ps";
    if (d.includes("xbox")) return "dev-xbox";
    if (d.includes("nintendo") || d.includes("switch")) return "dev-nin";
    if (d.includes("router") || d.includes("network gear") || d.includes("gateway") || d.includes("access point")) return "dev-net";
    if (d.includes("iot") || d.includes("camera") || d.includes("echo") || d.includes("hue") || d.includes("sonos") || d.includes("roku")) return "dev-iot";
    if (d.includes("virtual")) return "dev-vm";
    return "";
  };

  function render(data) {
    const body = $("#net-body"), table = $("#net-table"), empty = $("#net-empty"), summary = $("#net-summary");
    const hosts = data.hosts || [];
    body.innerHTML = "";
    table.hidden = hosts.length === 0;
    empty.hidden = hosts.length > 0;
    if (!hosts.length) {
      empty.innerHTML = "<div class=\"empty-icon\">◇</div><p>No hosts found on " + escapeHtml(data.cidr || "the subnet") + ".</p>";
    }
    const frag = document.createDocumentFragment();
    hosts.forEach(h => {
      const tr = document.createElement("tr");
      if (h.is_self) tr.className = "net-self";
      const dcls = deviceClass(h.device);
      tr.innerHTML =
        `<td><span class="st-ip clickable" data-capfilter="host ${escapeHtml(h.ip)}" title="Filter the capture by ${escapeHtml(h.ip)}">${escapeHtml(h.ip)}</span>${h.is_self ? ' <span class="net-tag">this host</span>' : ""}</td>` +
        `<td class="dim">${escapeHtml(h.mac || "—")}</td>` +
        `<td>${escapeHtml(h.vendor || "—")}</td>` +
        `<td><span class="dev-badge ${dcls}">${escapeHtml(h.device || "Unknown")}</span></td>` +
        `<td class="dim">${escapeHtml(h.hostname || "—")}</td>` +
        `<td class="net-actions"></td>`;
      const actions = tr.querySelector(".net-actions");
      const intelBtn = document.createElement("button");
      intelBtn.className = "btn btn-ghost net-mini";
      intelBtn.textContent = "Intel";
      intelBtn.title = "Look this address up in IP Intel";
      intelBtn.addEventListener("click", () => {
        if ($("#intel-ip")) $("#intel-ip").value = h.ip;
        if (typeof activateTab === "function") activateTab("intel");
        if (typeof lookupIP === "function") lookupIP();
      });
      actions.appendChild(intelBtn);
      if (!h.is_self) {
        const capBtn = document.createElement("button");
        capBtn.className = "btn btn-ghost net-mini";
        capBtn.textContent = "Intercept";
        capBtn.title = "Send this host to the Intercept tab to capture its traffic";
        capBtn.addEventListener("click", () => { if (typeof sendToIntercept === "function") sendToIntercept(h.ip); });
        actions.appendChild(capBtn);
      }
      frag.appendChild(tr);
    });
    body.appendChild(frag);

    summary.hidden = false;
    const consoles = hosts.filter(h => /playstation|xbox|nintendo|switch/i.test(h.device)).length;
    summary.innerHTML = `<b>${data.count}</b> host${data.count === 1 ? "" : "s"} on <b>${escapeHtml(data.cidr)}</b>` +
      ` · ${data.method === "arp" ? "active ARP sweep" : "neighbour cache"}` +
      (consoles ? ` · <b>${consoles}</b> game console${consoles === 1 ? "" : "s"}` : "") +
      (data.note ? ` · <span style="color:var(--amber)">${escapeHtml(data.note)}</span>` : "");
  }

  async function runScan() {
    const btn = $("#net-scan-btn");
    btn.disabled = true; btn.textContent = "Scanning…";
    $("#net-summary").hidden = false;
    $("#net-summary").innerHTML = "Sweeping the subnet…";
    $("#net-empty").hidden = true; $("#net-table").hidden = true;
    try {
      const body = {
        iface: $("#net-iface").value || null,
        cidr: $("#net-cidr").value.trim() || null,
        resolve: $("#net-resolve").checked,
      };
      const r = await fetch("/api/netscan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const data = await r.json();
      if (!r.ok) {
        $("#net-summary").innerHTML = `<span style="color:var(--red)">${escapeHtml(data.error || "Scan failed.")}</span>`;
        return;
      }
      render(data);
    } catch (e) {
      $("#net-summary").innerHTML = `<span style="color:var(--red)">${escapeHtml(String(e))}</span>`;
    } finally {
      btn.disabled = false; btn.textContent = "Scan network";
    }
  }

  /* click an IP in the results to filter the live capture */
  document.addEventListener("click", e => {
    const el = e.target.closest("#panel-netscan [data-capfilter]");
    if (!el) return;
    if (typeof applyCaptureFilter === "function") applyCaptureFilter(el.dataset.capfilter);
  });

  function init() {
    if (!$("#net-scan-btn")) return;
    loadNetIfaces();
    $("#net-iface").addEventListener("change", autoCidr);
    $("#net-scan-btn").addEventListener("click", runScan);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
