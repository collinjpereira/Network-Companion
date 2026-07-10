/* Incident response report builder. Schema-driven form following the SANS
   PICERL model and NIST SP 800-61 phases; auto-saves to localStorage and
   exports to Markdown, Word (.doc), or print/PDF.
   Relies on globals from app.js: $, $$, escapeHtml. */
(function () {
  const esc = (typeof escapeHtml === "function") ? escapeHtml
    : s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const LS_KEY = "networkcompanion_ir_report";
  const pad = n => String(n).padStart(2, "0");
  const now = new Date();
  const todayId = `INC-${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-001`;

  /* ---------- schema ---------- */
  const SCHEMA = [
    {
      num: "", title: "Incident Overview", desc: "Case metadata",
      fields: [
        { id: "report_title", label: "Report title", type: "text", value: "Security Incident Response Report", wide: true },
        { id: "incident_id", label: "Incident ID", type: "text", value: todayId },
        { id: "status", label: "Status", type: "select", value: "Under Investigation",
          options: ["Draft", "Under Investigation", "Contained", "Eradicated", "Recovering", "Closed"] },
        { id: "severity", label: "Severity", type: "select", value: "High",
          options: ["Critical", "High", "Medium", "Low", "Informational"] },
        { id: "priority", label: "Priority", type: "select", value: "P2",
          options: ["P1 – Emergency", "P2 – High", "P3 – Moderate", "P4 – Low"] },
        { id: "tlp", label: "Handling (TLP)", type: "select", value: "TLP:AMBER",
          options: ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"] },
        { id: "category", label: "Incident category", type: "select", value: "Unauthorized Access",
          options: ["Malware", "Ransomware", "Phishing / Social Engineering", "Unauthorized Access",
            "Account Compromise", "Data Breach / Exfiltration", "Denial of Service", "Insider Threat",
            "Reconnaissance / Scanning", "Web Application Attack", "Policy Violation", "Lost / Stolen Device", "Other"] },
        { id: "phase", label: "Current phase (PICERL)", type: "select", value: "Identification",
          options: ["Preparation", "Identification", "Containment", "Eradication", "Recovery", "Lessons Learned"] },
        { id: "occurred_at", label: "Occurred (earliest activity)", type: "datetime-local" },
        { id: "detected_at", label: "Detected", type: "datetime-local" },
        { id: "reported_at", label: "Reported", type: "datetime-local" },
        { id: "analyst", label: "Reporting analyst", type: "text", placeholder: "Your name" },
        { id: "handler", label: "Incident handler / lead", type: "text", placeholder: "Lead responder" },
        { id: "team", label: "Team", type: "text", value: "Security Operations Center (SOC)" },
        { id: "contact", label: "Contact (email / phone)", type: "text", placeholder: "soc@example.org" },
        { id: "org_unit", label: "Affected org / business unit", type: "text", placeholder: "e.g. Finance, Corp IT" },
      ],
    },
    {
      num: "1", title: "Executive Summary", desc: "Plain-language overview for leadership",
      fields: [
        { id: "exec_summary", label: "Summary", type: "textarea", wide: true, big: true,
          value: "On <date>, the SOC identified <brief description of the incident> affecting <systems/users>. "
            + "The activity was detected via <detection source>. Initial assessment rates this a <severity> incident "
            + "with <known/unknown> data impact. This report documents detection and analysis, scope and impact, "
            + "indicators of compromise, the response actions taken (containment, eradication, recovery), and lessons "
            + "learned. Current status: <e.g. contained; monitoring for recurrence>." },
      ],
    },
    {
      num: "2", title: "Detection & Analysis", desc: "How the incident surfaced",
      fields: [
        { id: "detection_source", label: "Detection source", type: "select", value: "SIEM alert",
          options: ["SIEM alert", "EDR / Antivirus", "IDS / IPS", "Firewall / proxy logs", "User / help-desk report",
            "Threat intelligence", "Proactive threat hunt", "Third party / vendor notification", "Honeypot / deception", "Other"] },
        { id: "detection_tool", label: "Detecting tool / product", type: "text", placeholder: "e.g. Splunk, CrowdStrike, Suricata" },
        { id: "detection_rule", label: "Alert / rule / signature ID", type: "text", placeholder: "e.g. SID 2027865, rule name" },
        { id: "confidence", label: "Analyst confidence", type: "select", value: "Medium", options: ["High", "Medium", "Low"] },
        { id: "first_indicator", label: "Initial indicator(s)", type: "textarea", wide: true,
          value: "What first signalled the incident (alert text, log line, user description)." },
        { id: "analysis", label: "Analysis & triage narrative", type: "textarea", wide: true, big: true,
          value: "Describe the investigation: what was observed, how the activity was validated as a true positive, "
            + "the suspected initial access vector, affected assets, and attacker actions on objectives. Note any "
            + "correlation across data sources (SIEM, EDR, network, authentication)." },
      ],
    },
    {
      num: "3", title: "Scope & Impact", desc: "What was affected",
      fields: [
        { id: "systems_count", label: "# systems affected", type: "text", placeholder: "e.g. 3" },
        { id: "users_count", label: "# users / accounts affected", type: "text", placeholder: "e.g. 2" },
        { id: "data_classification", label: "Data classification involved", type: "select", value: "Unknown",
          options: ["None", "Public", "Internal", "Confidential", "Restricted / Regulated (PII, PHI, PCI)", "Unknown"] },
        { id: "data_involved", label: "Data involved / exposure", type: "textarea", wide: true,
          value: "Describe any data accessed, modified, or exfiltrated, and whether it is regulated. Avoid pasting "
            + "actual sensitive records into this report." },
        { id: "business_impact", label: "Business impact", type: "textarea", wide: true,
          value: "Operational, financial, legal, and reputational impact. Include downtime and affected services." },
        { id: "affected_systems", label: "Affected systems", type: "table",
          cols: [
            { label: "Hostname" }, { label: "IP address" }, { label: "Role / function" }, { label: "OS" },
            { label: "Location" }, { label: "Status", type: "select", options: ["Compromised", "Suspected", "Isolated", "Cleaned", "Rebuilt", "Monitoring", "Clean"] },
          ],
          rows: [["", "", "", "", "", "Suspected"], ["", "", "", "", "", "Suspected"]] },
        { id: "affected_accounts", label: "Affected accounts", type: "table",
          cols: [
            { label: "Account / username" }, { label: "Type", type: "select", options: ["User", "Service", "Admin", "Domain Admin", "Shared", "Other"] },
            { label: "System / domain" }, { label: "Action taken", type: "select", options: ["None yet", "Password reset", "Disabled", "Sessions revoked", "MFA reset", "Deleted"] },
          ],
          rows: [["", "User", "", "None yet"]] },
      ],
    },
    {
      num: "4", title: "Indicators of Compromise (IOCs)", desc: "Atomic + host + network indicators",
      fields: [
        { id: "iocs", label: "Indicators", type: "table",
          cols: [
            { label: "Type", type: "select", options: ["IPv4", "IPv6", "Domain", "URL", "MD5", "SHA1", "SHA256", "Email", "Filename", "File path", "Registry key", "User-agent", "Mutex", "JA3", "Other"] },
            { label: "Indicator value" }, { label: "Context / where observed" },
            { label: "Confidence", type: "select", options: ["High", "Medium", "Low"] },
          ],
          rows: [["IPv4", "", "", "Medium"], ["Domain", "", "", "Medium"], ["SHA256", "", "", "Medium"], ["URL", "", "", "Medium"]] },
      ],
    },
    {
      num: "5", title: "MITRE ATT&CK Mapping", desc: "Adversary tactics & techniques observed",
      fields: [
        { id: "attack", label: "ATT&CK techniques", type: "table",
          cols: [
            { label: "Tactic" }, { label: "Technique ID" }, { label: "Technique name" }, { label: "Observed behaviour / evidence" },
          ],
          rows: [["Initial Access", "T1566", "Phishing", ""], ["Execution", "", "", ""], ["Persistence", "", "", ""], ["Command and Control", "", "", ""]] },
      ],
    },
    {
      num: "6", title: "Incident Timeline", desc: "Chronological reconstruction (use UTC)",
      fields: [
        { id: "timeline", label: "Timeline", type: "table",
          cols: [{ label: "Timestamp (UTC)" }, { label: "Event / activity" }, { label: "Source / evidence" }, { label: "Analyst" }],
          rows: [
            ["", "Earliest observed malicious activity", "", ""],
            ["", "Alert generated / incident detected", "", ""],
            ["", "Triage & investigation started", "", ""],
            ["", "Containment actions began", "", ""],
            ["", "Eradication completed", "", ""],
            ["", "Systems recovered / returned to service", "", ""],
          ] },
      ],
    },
    {
      num: "7", title: "Containment", desc: "Limit the damage",
      fields: [
        { id: "containment_checklist", label: "Containment checklist", type: "checklist", items: [
          "Isolate affected host(s) from the network",
          "Preserve volatile evidence (memory, processes, connections) before power actions",
          "Snapshot / image affected systems for forensics",
          "Disable or reset compromised accounts and credentials",
          "Revoke active sessions, tokens, and API keys",
          "Block malicious IPs / domains / hashes at firewall, proxy, and EDR",
          "Segment or quarantine the affected network zone",
          "Preserve and back up relevant logs (SIEM, EDR, firewall, auth, DNS)",
          "Notify the incident lead and required stakeholders",
        ] },
        { id: "short_term_containment", label: "Short-term containment actions", type: "textarea", wide: true,
          value: "Immediate steps taken to stop the bleeding (isolation, blocks, account disablement)." },
        { id: "long_term_containment", label: "Long-term / sustained containment", type: "textarea", wide: true,
          value: "Temporary fixes to keep systems usable while a permanent fix is prepared." },
        { id: "containment_at", label: "Containment achieved", type: "datetime-local" },
      ],
    },
    {
      num: "8", title: "Eradication", desc: "Remove the threat",
      fields: [
        { id: "eradication_checklist", label: "Eradication checklist", type: "checklist", items: [
          "Remove malware and malicious artifacts",
          "Delete attacker persistence (scheduled tasks, services, run keys, cron, webshells)",
          "Close the exploited vulnerability / apply patches",
          "Remove unauthorized accounts and access",
          "Rotate all potentially exposed credentials and secrets",
          "Rebuild compromised systems from known-good images where warranted",
          "Confirm no remaining attacker access (C2 beacons, backdoors)",
        ] },
        { id: "root_cause", label: "Root cause", type: "textarea", wide: true,
          value: "The underlying vulnerability, misconfiguration, or human factor that enabled the incident." },
        { id: "eradication_actions", label: "Eradication actions taken", type: "textarea", wide: true,
          value: "Malware removed, persistence cleared, patches applied, systems rebuilt." },
      ],
    },
    {
      num: "9", title: "Recovery", desc: "Restore to normal operations",
      fields: [
        { id: "recovery_checklist", label: "Recovery checklist", type: "checklist", items: [
          "Restore systems from clean, verified backups",
          "Patch and harden systems before returning to production",
          "Verify system and data integrity",
          "Apply heightened monitoring / alerting on restored systems",
          "Confirm business functionality with system owners",
          "Return systems to production in a controlled manner",
          "Remove temporary containment controls once safe",
        ] },
        { id: "recovery_actions", label: "Recovery actions", type: "textarea", wide: true,
          value: "How systems and services were restored and validated." },
        { id: "validation", label: "Validation & monitoring", type: "textarea", wide: true,
          value: "How you confirmed the threat is gone and what monitoring remains in place." },
        { id: "recovered_at", label: "Returned to operations", type: "datetime-local" },
      ],
    },
    {
      num: "10", title: "Communications & Notifications", desc: "Who was told, and when",
      fields: [
        { id: "regulatory_required", label: "Regulatory / legal notification required?", type: "select", value: "Undetermined",
          options: ["No", "Yes", "Undetermined"] },
        { id: "law_enforcement", label: "Law enforcement involved?", type: "select", value: "No", options: ["No", "Yes", "N/A"] },
        { id: "comms_log", label: "Notification log", type: "table",
          cols: [{ label: "Party / stakeholder" }, { label: "Method" }, { label: "Date / time" }, { label: "Notified by" }, { label: "Notes" }],
          rows: [["SOC Manager", "", "", "", ""], ["IT Operations", "", "", "", ""], ["Legal / Compliance", "", "", "", ""], ["Affected system owner", "", "", "", ""]] },
      ],
    },
    {
      num: "11", title: "Evidence & Chain of Custody", desc: "Forensic artifacts collected",
      fields: [
        { id: "evidence", label: "Evidence register", type: "table",
          cols: [{ label: "Evidence item" }, { label: "Source system" }, { label: "Collected by" }, { label: "Date / time (UTC)" }, { label: "Storage location" }, { label: "Hash (SHA256)" }],
          rows: [["", "", "", "", "", ""]] },
        { id: "tools_used", label: "Tools used in the investigation", type: "textarea", wide: true,
          value: "e.g. Network Companion packet capture, Wireshark, Volatility, EDR console, SIEM queries." },
      ],
    },
    {
      num: "12", title: "Post-Incident / Lessons Learned", desc: "Improve for next time",
      fields: [
        { id: "what_worked", label: "What worked well", type: "textarea", wide: true },
        { id: "what_to_improve", label: "What to improve", type: "textarea", wide: true },
        { id: "detection_gaps", label: "Detection / prevention gaps identified", type: "textarea", wide: true },
        { id: "action_items", label: "Action items", type: "table",
          cols: [{ label: "Action item" }, { label: "Owner" }, { label: "Priority", type: "select", options: ["High", "Medium", "Low"] }, { label: "Due date" }, { label: "Status", type: "select", options: ["Open", "In progress", "Done", "Deferred"] }],
          rows: [["", "", "High", "", "Open"], ["", "", "Medium", "", "Open"]] },
      ],
    },
    {
      num: "13", title: "References & Sign-off", desc: "Appendix and approvals",
      fields: [
        { id: "references", label: "References & related tickets", type: "textarea", wide: true,
          value: "Related alerts, ticket numbers, threat-intel reports, KB articles, playbooks used." },
        { id: "prepared_by", label: "Prepared by", type: "text" },
        { id: "reviewed_by", label: "Reviewed by", type: "text" },
        { id: "approved_by", label: "Approved by", type: "text" },
        { id: "closed_at", label: "Date closed", type: "date" },
      ],
    },
  ];

  const FIELD_BY_ID = {};
  SCHEMA.forEach(s => s.fields.forEach(f => { FIELD_BY_ID[f.id] = f; }));

  /* ---------- render ---------- */
  function el(tag, cls, html) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html != null) e.innerHTML = html;
    return e;
  }

  function renderTable(field) {
    const wrap = el("div", "ir-table-wrap");
    const table = el("table", "ir-table");
    table.dataset.field = field.id;
    const thead = el("thead");
    const htr = el("tr");
    field.cols.forEach(c => htr.appendChild(el("th", null, esc(c.label))));
    htr.appendChild(el("th", "ir-td-del", ""));
    thead.appendChild(htr);
    table.appendChild(thead);
    const tbody = el("tbody");
    table.appendChild(tbody);
    wrap.appendChild(table);
    const addBtn = el("button", "btn btn-ghost ir-add-row", "+ Add row");
    addBtn.type = "button";
    addBtn.addEventListener("click", () => { addRow(tbody, field); scheduleSave(); });
    wrap.appendChild(addBtn);
    (field.rows || [[]]).forEach(r => addRow(tbody, field, r));
    return wrap;
  }

  function addRow(tbody, field, values) {
    const tr = el("tr");
    field.cols.forEach((c, i) => {
      const td = el("td");
      const v = values && values[i] != null ? values[i] : (c.type === "select" && c.options ? c.options[0] : "");
      let input;
      if (c.type === "select") {
        input = el("select");
        c.options.forEach(o => { const op = el("option"); op.value = o; op.textContent = o; input.appendChild(op); });
        input.value = v;
      } else {
        input = el("input");
        input.type = "text";
        input.value = v;
      }
      input.addEventListener("input", scheduleSave);
      input.addEventListener("change", scheduleSave);
      td.appendChild(input);
      tr.appendChild(td);
    });
    const del = el("td", "ir-td-del");
    const db = el("button", "ir-row-del", "×");
    db.type = "button";
    db.title = "Remove row";
    db.addEventListener("click", () => { tr.remove(); scheduleSave(); });
    del.appendChild(db);
    tr.appendChild(del);
    tbody.appendChild(tr);
  }

  function renderField(field) {
    if (field.type === "table") {
      const box = el("div", "ir-field wide");
      box.appendChild(el("label", null, esc(field.label)));
      box.appendChild(renderTable(field));
      return box;
    }
    if (field.type === "checklist") {
      const box = el("div", "ir-field wide");
      box.appendChild(el("label", null, esc(field.label)));
      const list = el("div", "ir-checklist");
      list.dataset.field = field.id;
      field.items.forEach((item, i) => {
        const lab = el("label", "ir-check");
        const cb = el("input");
        cb.type = "checkbox";
        cb.dataset.item = item;
        cb.addEventListener("change", scheduleSave);
        lab.appendChild(cb);
        lab.appendChild(el("span", null, esc(item)));
        list.appendChild(lab);
      });
      box.appendChild(list);
      return box;
    }
    const box = el("div", "ir-field" + (field.wide || field.type === "textarea" ? " wide" : ""));
    const lab = el("label", null, esc(field.label));
    box.appendChild(lab);
    let input;
    if (field.type === "textarea") {
      input = el("textarea");
      if (field.big) input.rows = 6;
      if (field.value) input.value = field.value;
      if (field.placeholder) input.placeholder = field.placeholder;
    } else if (field.type === "select") {
      input = el("select");
      field.options.forEach(o => { const op = el("option"); op.value = o; op.textContent = o; input.appendChild(op); });
      if (field.value) input.value = field.value;
    } else {
      input = el("input");
      input.type = field.type || "text";
      if (field.value) input.value = field.value;
      if (field.placeholder) input.placeholder = field.placeholder;
    }
    input.id = "irf-" + field.id;
    input.dataset.field = field.id;
    input.addEventListener("input", scheduleSave);
    input.addEventListener("change", scheduleSave);
    box.appendChild(input);
    return box;
  }

  function buildForm() {
    const form = $("#ir-form");
    if (!form) return;
    form.innerHTML = "";
    SCHEMA.forEach(sec => {
      const section = el("section", "ir-section");
      const head = el("div", "ir-sec-head");
      if (sec.num) head.appendChild(el("span", "ir-sec-num", sec.num));
      head.appendChild(el("h3", null, esc(sec.title)));
      if (sec.desc) head.appendChild(el("span", "ir-sec-desc", esc(sec.desc)));
      section.appendChild(head);
      const body = el("div", "ir-sec-body");
      const grid = el("div", "ir-grid");
      sec.fields.forEach(f => grid.appendChild(renderField(f)));
      body.appendChild(grid);
      section.appendChild(body);
      form.appendChild(section);
    });
  }

  /* ---------- collect / restore ---------- */
  function collect() {
    const data = { values: {}, checks: {}, tables: {} };
    SCHEMA.forEach(sec => sec.fields.forEach(f => {
      if (f.type === "table") {
        const table = document.querySelector(`table.ir-table[data-field="${f.id}"]`);
        const rows = [];
        if (table) table.querySelectorAll("tbody tr").forEach(tr => {
          const cells = [...tr.querySelectorAll("td input, td select")].map(i => i.value);
          rows.push(cells);
        });
        data.tables[f.id] = rows;
      } else if (f.type === "checklist") {
        const cont = document.querySelector(`.ir-checklist[data-field="${f.id}"]`);
        const map = {};
        if (cont) cont.querySelectorAll("input[type=checkbox]").forEach(cb => { map[cb.dataset.item] = cb.checked; });
        data.checks[f.id] = map;
      } else {
        const inp = document.getElementById("irf-" + f.id);
        if (inp) data.values[f.id] = inp.value;
      }
    }));
    return data;
  }

  function restore(data) {
    if (!data) return;
    SCHEMA.forEach(sec => sec.fields.forEach(f => {
      if (f.type === "table" && data.tables && data.tables[f.id]) {
        const table = document.querySelector(`table.ir-table[data-field="${f.id}"]`);
        if (!table) return;
        const tbody = table.querySelector("tbody");
        tbody.innerHTML = "";
        const rows = data.tables[f.id].length ? data.tables[f.id] : (f.rows || [[]]);
        rows.forEach(r => addRow(tbody, f, r));
      } else if (f.type === "checklist" && data.checks && data.checks[f.id]) {
        const cont = document.querySelector(`.ir-checklist[data-field="${f.id}"]`);
        if (!cont) return;
        cont.querySelectorAll("input[type=checkbox]").forEach(cb => { cb.checked = !!data.checks[f.id][cb.dataset.item]; });
      } else if (data.values && data.values[f.id] != null) {
        const inp = document.getElementById("irf-" + f.id);
        if (inp) inp.value = data.values[f.id];
      }
    }));
  }

  let saveTimer = null;
  function scheduleSave() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      try {
        localStorage.setItem(LS_KEY, JSON.stringify(collect()));
        const s = $("#ir-saved");
        if (s) { s.textContent = "Draft saved " + new Date().toLocaleTimeString(); }
      } catch (e) {}
    }, 500);
  }

  const val = (d, id) => (d.values && d.values[id]) || "";
  function nonEmptyRows(rows) { return (rows || []).filter(r => r.some(c => (c || "").trim() !== "")); }

  /* ---------- Markdown export ---------- */
  function toMarkdown(d) {
    const lines = [];
    lines.push("# " + (val(d, "report_title") || "Security Incident Response Report"));
    lines.push("");
    lines.push(`*${val(d, "incident_id")} · ${val(d, "severity")} severity · ${val(d, "tlp")} · generated ${now.toISOString().slice(0, 16).replace("T", " ")} UTC*`);
    SCHEMA.forEach(sec => {
      lines.push("");
      lines.push(`## ${sec.num ? sec.num + ". " : ""}${sec.title}`);
      sec.fields.forEach(f => {
        if (f.type === "table") {
          const rows = nonEmptyRows(d.tables[f.id]);
          lines.push("");
          lines.push("### " + f.label);
          if (!rows.length) { lines.push("_None recorded._"); return; }
          lines.push("| " + f.cols.map(c => c.label).join(" | ") + " |");
          lines.push("| " + f.cols.map(() => "---").join(" | ") + " |");
          rows.forEach(r => lines.push("| " + r.map(c => String(c || "").replace(/\|/g, "\\|").replace(/\n/g, " ")).join(" | ") + " |"));
        } else if (f.type === "checklist") {
          lines.push("");
          lines.push("### " + f.label);
          const map = d.checks[f.id] || {};
          f.items.forEach(it => lines.push(`- [${map[it] ? "x" : " "}] ${it}`));
        } else {
          const v = val(d, f.id);
          if (v && v.trim()) lines.push(`**${f.label}:** ${v.replace(/\n/g, "  \n")}`);
        }
      });
    });
    lines.push("");
    lines.push("---");
    lines.push("*Generated with Network Companion.*");
    return lines.join("\n");
  }

  /* ---------- shared HTML report ---------- */
  const THEME = {
    heading: "#1b2a4a", accent: "#1f6f6c", gray: "#666666", cellBorder: "#cccccc",
  };

  function metaTable(d) {
    const pairs = [
      ["Incident ID", val(d, "incident_id")], ["Status", val(d, "status")],
      ["Severity", val(d, "severity")], ["Priority", val(d, "priority")],
      ["Category", val(d, "category")], ["Current phase", val(d, "phase")],
      ["Handling", val(d, "tlp")], ["Occurred", val(d, "occurred_at")],
      ["Detected", val(d, "detected_at")], ["Reported", val(d, "reported_at")],
      ["Reporting analyst", val(d, "analyst")], ["Incident handler", val(d, "handler")],
      ["Team", val(d, "team")], ["Contact", val(d, "contact")],
      ["Affected org / unit", val(d, "org_unit")],
    ].filter(p => (p[1] || "").trim() !== "");
    let rows = "";
    for (let i = 0; i < pairs.length; i += 2) {
      const a = pairs[i], b = pairs[i + 1];
      rows += `<tr><td class="mk">${esc(a[0])}</td><td>${esc(a[1])}</td>`
        + (b ? `<td class="mk">${esc(b[0])}</td><td>${esc(b[1])}</td>` : `<td></td><td></td>`) + `</tr>`;
    }
    return `<table class="meta">${rows}</table>`;
  }

  function reportBody(d) {
    let html = "";
    SCHEMA.forEach(sec => {
      if (!sec.num) return; // overview handled by meta table
      html += `<h1>${sec.num}. ${esc(sec.title)}</h1>`;
      sec.fields.forEach(f => {
        if (f.type === "table") {
          const rows = nonEmptyRows(d.tables[f.id]);
          html += `<h2>${esc(f.label)}</h2>`;
          if (!rows.length) { html += `<p class="empty">None recorded.</p>`; return; }
          html += `<table class="data"><thead><tr>${f.cols.map(c => `<th>${esc(c.label)}</th>`).join("")}</tr></thead><tbody>`;
          rows.forEach(r => { html += `<tr>${f.cols.map((c, i) => `<td>${esc(r[i] || "")}</td>`).join("")}</tr>`; });
          html += `</tbody></table>`;
        } else if (f.type === "checklist") {
          html += `<h2>${esc(f.label)}</h2><ul class="check">`;
          const map = d.checks[f.id] || {};
          f.items.forEach(it => { html += `<li>${map[it] ? "&#9745;" : "&#9744;"} ${esc(it)}</li>`; });
          html += `</ul>`;
        } else {
          const v = val(d, f.id);
          if (v && v.trim()) html += `<h3>${esc(f.label)}</h3><p>${esc(v).replace(/\n/g, "<br>")}</p>`;
        }
      });
    });
    return html;
  }

  function buildReportHtml(d, forWord) {
    const title = val(d, "report_title") || "Security Incident Response Report";
    const subtitle = `${val(d, "incident_id")} &nbsp;·&nbsp; ${val(d, "severity")} severity &nbsp;·&nbsp; ${val(d, "tlp")} &nbsp;·&nbsp; ${esc(now.toISOString().slice(0, 10))}`;
    const footerNote = "Generated with Network Companion";
    const msoHF = forWord ? `
      <!--[if gte mso 9]><xml><w:WordDocument><w:View>Print</w:View><w:Zoom>100</w:Zoom></w:WordDocument></xml><![endif]-->
      <div style='mso-element:header' id=h1><p class=MsoHeader style='border-bottom:.75pt solid ${THEME.heading};'>
        <span style='color:${THEME.heading};font-weight:bold'>Network Companion</span><span style='mso-tab-count:1'></span>Incident Response Report</p></div>
      <div style='mso-element:footer' id=f1><p class=MsoFooter style='border-top:.75pt solid ${THEME.heading};font-size:8pt;color:${THEME.gray}'>
        ${esc(footerNote)}<span style='mso-tab-count:1'></span>Page <span style='mso-field-code:PAGE'></span></p></div>` : "";
    const style = `
      @page Section1 { size: 8.5in 11in; margin: 1in; ${forWord ? "mso-header: h1; mso-footer: f1; mso-header-margin:.5in; mso-footer-margin:.5in;" : ""} }
      div.Section1 { page: Section1; }
      * { box-sizing: border-box; }
      body { font-family: Calibri, "Segoe UI", Arial, sans-serif; color: #1a1a1a; font-size: 11pt; line-height: 1.4; margin: ${forWord ? "0" : "0"}; background: #fff; }
      .page { ${forWord ? "" : "max-width: 8.5in; margin: 0 auto; padding: 1in; min-height: 11in;"} background: #fff; }
      .doc-header { display: flex; justify-content: space-between; align-items: baseline; border-bottom: 1px solid ${THEME.heading}; padding-bottom: 4px; margin-bottom: 22px; font-size: 10pt; }
      .doc-header .brand { color: ${THEME.heading}; font-weight: bold; }
      .title-block { text-align: center; margin-bottom: 26px; }
      .title-block h1 { font-size: 26pt; font-weight: bold; color: ${THEME.heading}; margin: 0; border: none; }
      .title-rule { height: 3px; background: ${THEME.accent}; width: 60%; margin: 8px auto 6px; }
      .title-block .sub { font-size: 11pt; color: ${THEME.gray}; }
      h1 { font-size: 16pt; font-weight: bold; color: ${THEME.heading}; border-bottom: 1px solid ${THEME.heading}; padding-bottom: 3px; margin: 22px 0 10px; }
      h2 { font-size: 13pt; font-weight: bold; color: ${THEME.heading}; margin: 14px 0 6px; }
      h3 { font-size: 12pt; font-weight: bold; color: ${THEME.accent}; margin: 12px 0 4px; }
      p { margin: 4px 0 10px; }
      p.empty { color: ${THEME.gray}; font-style: italic; }
      table { border-collapse: collapse; width: 100%; margin: 6px 0 14px; }
      table.meta td { border: 1px solid ${THEME.cellBorder}; padding: 5px 8px; font-size: 10.5pt; vertical-align: top; }
      table.meta td.mk { background: #f3f3f6; color: ${THEME.heading}; font-weight: bold; width: 16%; }
      table.data th { background: ${THEME.heading}; color: #fff; text-align: left; padding: 6px 8px; font-size: 10pt; border: 1px solid ${THEME.cellBorder}; }
      table.data td { border: 1px solid ${THEME.cellBorder}; padding: 5px 8px; font-size: 10pt; vertical-align: top; color: #000; }
      table.data tr:nth-child(even) td { background: #f9f9f9; }
      ul.check { list-style: none; padding-left: 0; margin: 6px 0 12px; }
      ul.check li { padding: 2px 0; font-size: 10.5pt; }
      .note { background: #f9f9f9; border: 1px solid ${THEME.cellBorder}; border-left: 4px solid ${THEME.accent}; padding: 8px 12px; margin: 10px 0; font-size: 10pt; }
      .note .lbl { color: ${THEME.accent}; font-weight: bold; }
      .doc-footer { margin-top: 26px; border-top: 1px solid ${THEME.heading}; padding-top: 6px; font-size: 8pt; color: ${THEME.gray}; }
      @media print { .page { margin: 0; max-width: none; padding: 0; } }
    `;
    const sevNote = `<div class="note"><span class="lbl">NOTE&nbsp;</span> This is a ${esc(val(d, "severity"))}-severity ${esc(val(d, "category"))} incident, currently in the ${esc(val(d, "phase"))} phase (${esc(val(d, "status"))}). Handling marking: ${esc(val(d, "tlp"))}.</div>`;
    return `<!DOCTYPE html><html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word" xmlns="http://www.w3.org/TR/REC-html40">
<head><meta charset="utf-8"><title>${esc(title)}</title>${msoHF}<style>${style}</style></head>
<body><div class="Section1"><div class="page">
  <div class="doc-header"><span class="brand">Network Companion</span><span>Incident Response Report &nbsp;·&nbsp; ${esc(val(d, "tlp"))}</span></div>
  <div class="title-block"><h1>${esc(title)}</h1><div class="title-rule"></div><div class="sub">${subtitle}</div></div>
  ${sevNote}
  ${metaTable(d)}
  ${reportBody(d)}
  <div class="doc-footer">${esc(footerNote)}</div>
</div></div></body></html>`;
  }

  /* ---------- download helpers ---------- */
  function download(filename, mime, content) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }
  function slug(d) {
    return (val(d, "incident_id") || "incident").replace(/[^\w.-]+/g, "_");
  }

  /* ---------- wire toolbar ---------- */
  function init() {
    if (!$("#ir-form")) return;
    buildForm();
    try {
      const saved = localStorage.getItem(LS_KEY);
      if (saved) restore(JSON.parse(saved));
    } catch (e) {}

    $("#ir-print").addEventListener("click", () => {
      const html = buildReportHtml(collect(), false);
      const w = window.open("", "_blank");
      if (!w) { alert("Pop-up blocked. Allow pop-ups to print the report."); return; }
      w.document.open(); w.document.write(html); w.document.close();
      w.focus();
      setTimeout(() => { try { w.print(); } catch (e) {} }, 400);
    });
    $("#ir-word").addEventListener("click", () => {
      const d = collect();
      download(slug(d) + ".doc", "application/msword", buildReportHtml(d, true));
    });
    $("#ir-md").addEventListener("click", () => {
      const d = collect();
      download(slug(d) + ".md", "text/markdown;charset=utf-8", toMarkdown(d));
    });
    $("#ir-save-json").addEventListener("click", () => {
      const d = collect();
      download(slug(d) + ".json", "application/json", JSON.stringify(d, null, 2));
    });
    $("#ir-load-json").addEventListener("click", () => $("#ir-json-input").click());
    $("#ir-json-input").addEventListener("change", async e => {
      const file = e.target.files[0]; if (!file) return;
      try {
        const text = await file.text();
        restore(JSON.parse(text));
        scheduleSave();
      } catch (err) { alert("Could not read that draft: " + err.message); }
      e.target.value = "";
    });
    $("#ir-reset").addEventListener("click", () => {
      if (!confirm("Clear the form back to the blank template? This discards the current draft.")) return;
      localStorage.removeItem(LS_KEY);
      buildForm();
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
