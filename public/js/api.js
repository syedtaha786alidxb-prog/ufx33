async function api(method, url, body) {
  const opts = { method, headers: { "Content-Type": "application/json" } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  if (res.status === 401) { window.location.href = "/login.html"; throw new Error("Not logged in"); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}
function toast(msg, type = "") {
  let t = document.getElementById("toast");
  if (!t) {
    t = document.createElement("div");
    t.id = "toast";
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.className = "toast show " + type;
  clearTimeout(window._toastTimer);
  window._toastTimer = setTimeout(() => (t.className = "toast " + type), 2500);
}
function fmt(n) {
  return (Math.round((n || 0) * 100) / 100).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}
function getCurrentJobId() { return localStorage.getItem("hd_current_job_id") || ""; }
function setCurrentJobId(id) { localStorage.setItem("hd_current_job_id", id); }

async function renderTopNav(active) {
  const groups = [
    { key: "job", label: "Job", items: [
      ["job/booking.html", "Booking Info"],
      ["job/tariff.html", "Tariff"],
      ["job/bl.html", "B/L & Containers"],
      ["job/invoice.html", "Invoice"],
      ["job/jobbill.html", "Job Bill"],
      ["job/joblist.html", "Job List"],
    ]},
    { key: "accounting", label: "Accounting", items: [
      ["accounting/coa.html", "Chart of Accounts"],
      ["accounting/vouchers.html", "Vouchers"],
      ["accounting/ledger.html", "Ledger"],
      ["accounting/receivables.html", "Receivables"],
      ["accounting/payables.html", "Payables"],
      ["accounting/credit-notes.html", "Credit Notes"],
      ["accounting/debit-notes.html", "Debit Notes"],
      ["accounting/trialbalance.html", "Trial Balance"],
      ["accounting/bankrecon.html", "Bank Reconciliation"],
      ["admin/charge-codes.html", "Charge Codes"],
    ]},
    { key: "admin", label: "Admin", items: [
      ["admin/vessels.html", "Vessels & Voyages"],
      ["admin/parties.html", "Customers & Vendors"],
      ["admin/commodities.html", "Commodities"],
      ["admin/ports.html", "Ports"],
      ["admin/users.html", "Users & Access"],
      ["admin/settings.html", "Settings"],
      ["admin/opening-balances.html", "Opening Balances"],
      ["admin/currencies.html", "Currency & Exchange Rate"],
      ["admin/logs.html", "Logs"],
    ]},
    { key: "reports", label: "Reports", items: [
      ["reports/index.html", "Reports"],
      ["reports/pl.html", "Profit & Loss"],
      ["reports/balance-sheet.html", "Balance Sheet"],
      ["reports/cash-flow.html", "Cash Flow"],
    ]},
  ];
  const el = document.getElementById("topnav");
  if (!el) return;

  let me = null;
  try {
    const res = await fetch("/api/me");
    if (res.status === 401) { window.location.href = "/login.html"; return; }
    me = await res.json();
  } catch (e) { window.location.href = "/login.html"; return; }

  const company = await getCompanyProfile();
  const brandHtml = `<span class="brand">${company.logo ? `<img src="${company.logo}" style="height:24px;vertical-align:middle;margin-right:6px;border-radius:3px;">` : "🚢 "}${esc(company.name) || "Harbor Desk"}</span>`;

  // Chatbot-only accounts see nothing but the chatbot link + logout — no Dashboard, no other modules.
  if (me.chatbot_only) {
    el.innerHTML =
      brandHtml +
      `<a href="/chatbot.html" class="${active === "chatbot.html" ? "active" : ""}">🤖 Chatbot</a>` +
      `<a href="/gridview.html" class="${active === "gridview.html" ? "active" : ""}">📊 Grid View</a>` +
      `<span style="margin-left:auto;display:flex;align-items:center;gap:10px;">
         <span style="color:#8FA3B5;font-size:12.5px;">${esc(me.name)}</span>
         <a href="#" id="logoutLink" style="color:#F0A0A0;">Logout</a>
       </span>`;
    const logoutLink = document.getElementById("logoutLink");
    if (logoutLink) logoutLink.onclick = async (e) => {
      e.preventDefault();
      await fetch("/api/logout", { method: "POST" });
      window.location.href = "/login.html";
    };
    return me;
  }

  const allowedGroups = groups
    .filter(g => me.modules.includes(g.key))
    .map(g => ({ ...g, hasActive: g.items.some(([href]) => href === active) }));

  el.innerHTML =
    brandHtml +
    `<a href="/dashboard.html" class="${active === "dashboard.html" ? "active" : ""}">🏠 Dashboard</a>` +
    allowedGroups.map(g => `
      <div class="navgroup ${g.hasActive ? "active" : ""}">
        <button type="button" class="navgroup-btn">${g.label} <span class="navgroup-caret">▾</span></button>
        <div class="navgroup-menu">
          ${g.items.map(([href, label]) => `<a href="/${href}" class="${href === active ? "active" : ""}">${label}</a>`).join("")}
        </div>
      </div>`).join("") +
    (me.modules.includes("chatbot") ? `<a href="/chatbot.html" class="${active === "chatbot.html" ? "active" : ""}">🤖 Chatbot</a>` : "") +
    (me.modules.includes("chatbot") ? `<a href="/gridview.html" class="${active === "gridview.html" ? "active" : ""}">📊 Grid View</a>` : "") +
    `<span style="margin-left:auto;display:flex;align-items:center;gap:10px;">
       <span style="color:#8FA3B5;font-size:12.5px;">${esc(me.name)} (${esc(me.role)})</span>
       <a href="#" id="logoutLink" style="color:#F0A0A0;">Logout</a>
     </span>`;

  // Click-to-toggle dropdowns; clicking elsewhere closes them.
  const allGroupEls = [...el.querySelectorAll(".navgroup")];
  allGroupEls.forEach(g => {
    g.querySelector(".navgroup-btn").onclick = (e) => {
      e.stopPropagation();
      const isOpen = g.classList.contains("open");
      allGroupEls.forEach(x => x.classList.remove("open"));
      if (!isOpen) g.classList.add("open");
    };
  });
  document.addEventListener("click", () => allGroupEls.forEach(x => x.classList.remove("open")));

  const logoutLink = document.getElementById("logoutLink");
  if (logoutLink) logoutLink.onclick = async (e) => {
    e.preventDefault();
    await fetch("/api/logout", { method: "POST" });
    window.location.href = "/login.html";
  };
  return me;
}
function canDelete(me) { return !!(me && (me.can_delete || me.role === "Admin")); }

let _companyProfileCache = null;
async function getCompanyProfile() {
  if (_companyProfileCache) return _companyProfileCache;
  try { _companyProfileCache = await fetch("/api/company-profile").then(r => r.json()); }
  catch (e) { _companyProfileCache = { name: "", address: "", email: "", phone: "", logo: "" }; }
  return _companyProfileCache;
}
// Standard letterhead block for any printed document — used by every print function so every
// printout (vouchers, bills, credit/debit notes, invoices, exports) carries the same company
// branding, a report title, and (when given) the date range the data covers.
// dateRange: optional string like "01 Jan 2026 – 27 Sep 2026" describing the data's coverage.
function letterheadHtml(company, docTitle, docNo, dateRange) {
  return `
    <div style="display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2px solid #1C2A36;padding-bottom:12px;margin-bottom:20px;">
      <div style="display:flex;align-items:center;gap:12px;">
        ${company.logo ? `<img src="${company.logo}" style="max-height:50px;max-width:130px;">` : ""}
        <div><h2 style="margin:0;">${docTitle}</h2>${docNo ? `<div style="color:#5B6B78;font-size:13px;">${docNo}</div>` : ""}${dateRange ? `<div style="color:#5B6B78;font-size:12px;">Data period: ${dateRange}</div>` : ""}</div>
      </div>
      <div style="text-align:right;font-size:12px;">
        <div style="font-weight:700;font-size:14px;">${company.name || "Harbor Desk Shipping LLC"}</div>
        ${company.address ? `<div>${company.address}</div>` : ""}
        ${company.email ? `<div>${company.email}</div>` : ""}
        ${company.phone ? `<div>${company.phone}</div>` : ""}
      </div>
    </div>`;
}
// Print footer: company details + (for a print, not an on-screen view) the timestamp this was
// printed and which logged-in user printed it — so every hard copy is traceable back to who ran it.
function letterheadFooterHtml(company, printedByUser) {
  const parts = [company.name, company.address, company.email, company.phone].filter(Boolean);
  const stampLine = printedByUser
    ? `<div style="margin-top:4px;">Printed ${new Date().toLocaleString()} by ${esc(printedByUser)}</div>`
    : "";
  return (parts.length || stampLine)
    ? `<div style="border-top:1px solid #DBE1E7;margin-top:30px;padding-top:8px;font-size:11px;color:#5B6B78;text-align:center;">${parts.join(" · ")}${stampLine}</div>`
    : "";
}

// Escapes any free-typed text before it's dropped into an innerHTML template — without this, a party
// name, narration, or reason containing "<script>" or an onerror= attribute would execute in every
// browser that later views that record. ALWAYS wrap user-entered text with esc() before interpolating
// it into an innerHTML string; numbers, codes, and system-generated values (job_no, txn, bill_no) are
// safe as-is since they're never derived from raw free text.
function esc(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Shows a small modal asking for a mandatory reason/comment before a delete or cancellation proceeds.
// Resolves with the trimmed reason string, or null if the person cancelled — callers should bail out
// on null and never call the delete endpoint without a non-empty reason.
function confirmWithReason(title, detail) {
  return new Promise((resolve) => {
    let root = document.getElementById("modalRoot");
    if (!root) { root = document.createElement("div"); root.id = "modalRoot"; document.body.appendChild(root); }
    const prevHtml = root.innerHTML;
    root.innerHTML = `
      <div class="modal-backdrop">
        <div class="modal">
          <h3>${esc(title)}</h3>
          <p class="sub">${esc(detail) || "This can't be undone. Please explain why."}</p>
          <div class="field" style="margin-bottom:16px;"><label>Reason / Comment *</label><textarea id="reasonInput" rows="3" placeholder="Required — explain why this is being deleted/cancelled"></textarea></div>
          <div class="btn-row" style="margin-top:0;"><button class="btn" id="reasonCancelBtn">Cancel</button><button class="btn" style="background:var(--red,#C1442D);color:#fff;" id="reasonConfirmBtn">Confirm Delete</button></div>
        </div>
      </div>`;
    const cleanup = (val) => { root.innerHTML = prevHtml; resolve(val); };
    document.getElementById("reasonCancelBtn").onclick = () => cleanup(null);
    document.getElementById("reasonConfirmBtn").onclick = () => {
      const reason = document.getElementById("reasonInput").value.trim();
      if (!reason) { toast("A reason is required", "error"); return; }
      cleanup(reason);
    };
  });
}

// ---- Generic autocomplete: shows every item, and as the user types, suggests any item that has a
// word starting with what's typed (not just a whole-string match) — used for Client/Shipper/
// Consignee/Vendor pickers so nothing that's been added is ever hidden from the dropdown.
function attachAutocomplete(input, getItems, onPick) {
  if (!input.parentElement.classList.contains("ac-wrap")) {
    const wrap = document.createElement("div");
    wrap.className = "ac-wrap";
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);
  }
  const list = document.createElement("div");
  list.className = "ac-list";
  list.style.display = "none";
  input.parentElement.appendChild(list);

  function render(filterText) {
    const items = getItems();
    const q = (filterText || "").trim().toLowerCase();
    const matches = items.filter(it => {
      if (!q) return true;
      const words = it.label.toLowerCase().split(/\s+/);
      return words.some(w => w.startsWith(q)) || it.label.toLowerCase().includes(q);
    }).slice(0, 30);
    if (!matches.length) { list.style.display = "none"; return; }
    list.innerHTML = matches.map((it, i) => `<div class="ac-item" data-i="${i}">${esc(it.label)}${it.sub ? `<div class="ac-sub">${esc(it.sub)}</div>` : ""}</div>`).join("");
    list.style.display = "block";
    [...list.children].forEach((el, i) => {
      el.onmousedown = (e) => { e.preventDefault(); input.value = matches[i].label; list.style.display = "none"; onPick && onPick(matches[i]); };
    });
  }
  input.addEventListener("input", () => render(input.value));
  input.addEventListener("focus", () => render(input.value));
  input.addEventListener("blur", () => setTimeout(() => { list.style.display = "none"; }, 150));
}

// ---- Shared "export a data list to Excel" helper — used by Job List and any other list page so
// every exported file carries the same company letterhead, a report title, the date range the
// data covers, a sum row under numeric columns, and a footer noting who exported it and when.
// Requires the page to have loaded SheetJS (xlsx.full.min.js) before calling this.
// opts: { rows, columns:[{key,label,sum?:true}], reportTitle, dateRangeLabel, fileName, sheetName, user }
async function exportRowsToExcel(opts) {
  if (typeof XLSX === "undefined") { toast("Export library not loaded on this page", "error"); return; }
  const company = await getCompanyProfile();
  const cols = opts.columns;
  const aoa = [];
  aoa.push([company.name || "Harbor Desk Shipping LLC"]);
  if (company.address) aoa.push([company.address]);
  aoa.push([opts.reportTitle || "Report"]);
  if (opts.dateRangeLabel) aoa.push([`Data period: ${opts.dateRangeLabel}`]);
  aoa.push([]);
  aoa.push(cols.map(c => c.label));
  (opts.rows || []).forEach(r => aoa.push(cols.map(c => (typeof c.value === "function" ? c.value(r) : r[c.key]))));
  const sumRow = cols.map((c, i) => {
    if (i === 0) return "TOTAL";
    if (!c.sum) return "";
    const total = (opts.rows || []).reduce((s, r) => s + (Number(typeof c.value === "function" ? c.value(r) : r[c.key]) || 0), 0);
    return Math.round(total * 100) / 100;
  });
  aoa.push(sumRow);
  aoa.push([]);
  aoa.push([`Exported ${new Date().toLocaleString()}${opts.user ? " by " + opts.user : ""}`]);
  const ws = XLSX.utils.aoa_to_sheet(aoa);
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, opts.sheetName || "Data");
  XLSX.writeFile(wb, opts.fileName || "export.xlsx");
}

// ---- Job search-by-serial-number box: drop this into any job-related page so a job's own number
// (e.g. EXP-00001/26) can be typed in directly to jump straight to it, instead of hunting the Job List.
function renderJobSearchBox(containerId, onFound) {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = `
    <div class="jobsearch">
      <input id="jobSearchInput" placeholder="Enter Job # e.g. EXP-00001/26" class="mono" style="max-width:220px;">
      <button class="btn btn-sm btn-teal" id="jobSearchBtn">🔎 Search</button>
      <span class="sub">Jump straight to a job by its serial number</span>
    </div>`;
  const go = async () => {
    const no = document.getElementById("jobSearchInput").value.trim();
    if (!no) return toast("Enter a job number first", "error");
    try {
      const job = await api("GET", `/api/jobs/by-no/${encodeURIComponent(no)}`);
      setCurrentJobId(job.id);
      toast(`Found ${job.job_no}`, "success");
      if (onFound) onFound(job); else location.reload();
    } catch (e) { toast(e.message, "error"); }
  };
  document.getElementById("jobSearchBtn").onclick = go;
  document.getElementById("jobSearchInput").addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
}
