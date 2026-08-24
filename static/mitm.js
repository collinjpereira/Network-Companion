/* Intercept tab: ARP-redirects a target's traffic through this host so it
   can be captured and shaped. Authorised lab use only. Relies on globals
   from app.js: $, $$, escapeHtml, activateTab, state. */
(function () {
  let active = false;

  const SHAPE_PRESETS = {
    dsl: { rate: 2000, delay: 40, jitter: 10, loss: 0 },
    mobile: { rate: 750, delay: 120, jitter: 40, loss: 1 },
    lossy: { rate: null, delay: 30, jitter: 15, loss: 8 },
    lag: { rate: null, delay: 300, jitter: 80, loss: 2 },
  };

  async function loadIfaces() {
    const sel = $("#mitm-iface");
    if (!sel) return;
    try {
      const r = await fetch("/api/interfaces");
      const data = await r.json();
      sel.innerHTML = "";
      (data.interfaces || []).forEach(i => {
        const o = document.createElement("option");
        o.value = i.name;
        o.textContent = i.name + (i.ip ? " · " + i.ip : "");
        sel.appendChild(o);
      });
      if (!sel.options.length) { const o = document.createElement("option"); o.textContent = "no interfaces found"; sel.appendChild(o); }
    } catch (e) {}
  }

  function setState(txt, cls) {
    const el = $("#mitm-state");
    el.textContent = txt;
    el.className = "mitm-state" + (cls ? " " + cls : "");
  }

  function applyStatus(st) {
    active = !!st.active;
    $("#mitm-btn").textContent = active ? "Stop interception" : "Start interception";
    $("#mitm-btn").classList.toggle("recording", active);
    $("#mitm-capture").disabled = !active;
    ["mitm-iface", "mitm-target", "mitm-gateway", "mitm-bidir"].forEach(id => { const e = $("#" + id); if (e) e.disabled = active; });
    if (active) {
      setState("intercepting " + st.target, "live");
      const info = $("#mitm-info"); info.hidden = false;
      info.innerHTML =
        `<div><span class="k">Target</span> ${escapeHtml(st.target)} <span class="dim">(${escapeHtml(st.target_mac || "?")})</span></div>` +
        `<div><span class="k">Gateway</span> ${escapeHtml(st.gateway)} <span class="dim">(${escapeHtml(st.gateway_mac || "?")})</span></div>` +
        `<div><span class="k">Via</span> ${escapeHtml(st.iface || "?")} <span class="dim">(${escapeHtml(st.our_mac || "?")})</span> · ${st.bidirectional ? "both directions" : "target only"}</div>` +
        `<div><span class="k">ARP sent</span> ${st.arp_sent || 0} <span class="dim">forwarding: ${st.forwarding_ok ? "confirmed on" : "NOT confirmed (" + escapeHtml(st.platform || "?") + ")"}</span></div>`;
    } else {
      setState("idle", "");
      $("#mitm-info").hidden = true;
    }
    const warnBox = $("#mitm-warnings");
    if (warnBox) {
      const warnings = st.warnings || [];
      if (warnings.length) {
        warnBox.hidden = false;
        warnBox.innerHTML = warnings.map(w => `<div>${escapeHtml(w)}</div>`).join("");
      } else {
        warnBox.hidden = true;
        warnBox.innerHTML = "";
      }
    }
    const sh = st.shaping;
    const ss = $("#shape-state");
    if (sh) {
      const bits = [];
      if (sh.delay_ms != null) bits.push(sh.delay_ms + "ms" + (sh.jitter_ms != null ? "±" + sh.jitter_ms : ""));
      if (sh.loss_pct != null) bits.push(sh.loss_pct + "% loss");
      if (sh.rate_kbit != null) bits.push(sh.rate_kbit + "kbit");
      ss.textContent = "shaping: " + bits.join(" · ");
      ss.className = "mitm-substate on";
    } else {
      ss.textContent = "no shaping";
      ss.className = "mitm-substate";
    }
  }

  async function refresh() {
    try {
      const r = await fetch("/api/mitm/status");
      applyStatus(await r.json());
    } catch (e) {}
  }

  async function toggle() {
    const btn = $("#mitm-btn");
    btn.disabled = true;
    try {
      if (active) {
        await fetch("/api/mitm/stop", { method: "POST" });
        await refresh();
      } else {
        const target = $("#mitm-target").value.trim();
        if (!target) { alert("Enter the target IP to intercept."); return; }
        if (!confirm("Confirm you own " + target + " or have explicit authorisation to intercept its traffic.\n\n" +
          "Intercepting traffic without authorisation is illegal. Continue?")) return;
        setState("starting…", "");
        const body = {
          iface: $("#mitm-iface").value || null,
          target,
          gateway: $("#mitm-gateway").value.trim() || null,
          bidirectional: $("#mitm-bidir").checked,
        };
        const r = await fetch("/api/mitm/start", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
        const data = await r.json();
        if (!r.ok) { setState("error", "error"); alert(data.error || "Could not start interception."); return; }
        applyStatus(data);
      }
    } catch (e) { alert(String(e)); }
    finally { btn.disabled = false; }
  }

  async function applyShaping() {
    const body = {
      rate_kbit: parseFloat($("#shape-rate").value) || null,
      delay_ms: parseFloat($("#shape-delay").value) || null,
      jitter_ms: parseFloat($("#shape-jitter").value) || null,
      loss_pct: parseFloat($("#shape-loss").value) || null,
    };
    try {
      const r = await fetch("/api/mitm/shape", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const data = await r.json();
      if (!r.ok) { alert(data.error || "Could not apply shaping."); return; }
      await refresh();
    } catch (e) { alert(String(e)); }
  }

  async function clearShaping() {
    try {
      await fetch("/api/mitm/shape", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({}) });
      ["shape-rate", "shape-delay", "shape-jitter", "shape-loss"].forEach(id => { $("#" + id).value = ""; });
      await refresh();
    } catch (e) {}
  }

  function captureTarget() {
    const target = $("#mitm-target").value.trim();
    if (!target) return;
    // Capture MUST run on the same interface the interception uses, otherwise
    // it sniffs the wrong NIC and sees nothing.
    const mif = $("#mitm-iface").value;
    const capIface = $("#iface");
    if (capIface && mif) {
      if (![...capIface.options].some(o => o.value === mif)) {
        const o = document.createElement("option"); o.value = mif; o.textContent = mif; capIface.appendChild(o);
      }
      capIface.value = mif;
    }
    const bpf = $("#bpf");
    if (bpf) bpf.value = "host " + target;
    if (typeof activateTab === "function") activateTab("capture");
    const cb = $("#capture-btn");
    if (!cb || typeof state === "undefined") return;
    // (Re)start capture so the interface + filter actually take effect.
    if (state.running) { cb.click(); setTimeout(() => cb.click(), 500); }
    else { cb.click(); }
  }

  function init() {
    if (!$("#mitm-btn")) return;
    loadIfaces();
    refresh();
    $("#mitm-btn").addEventListener("click", toggle);
    $("#mitm-capture").addEventListener("click", captureTarget);
    $("#shape-apply").addEventListener("click", applyShaping);
    $("#shape-clear").addEventListener("click", clearShaping);
    $$("[data-shape]").forEach(b => b.addEventListener("click", () => {
      const p = SHAPE_PRESETS[b.dataset.shape]; if (!p) return;
      $("#shape-rate").value = p.rate == null ? "" : p.rate;
      $("#shape-delay").value = p.delay == null ? "" : p.delay;
      $("#shape-jitter").value = p.jitter == null ? "" : p.jitter;
      $("#shape-loss").value = p.loss == null ? "" : p.loss;
    }));
    // keep status fresh while the tab is open
    setInterval(() => { if ($("#panel-mitm").classList.contains("active")) refresh(); }, 4000);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();

/* Expose a helper so the Network tab can hand a target to Intercept. */
function sendToIntercept(ip) {
  const t = document.querySelector("#mitm-target");
  if (t) t.value = ip;
  if (typeof activateTab === "function") activateTab("mitm");
}
