const express = require("express");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const db = require("./db");
const { XMLParser } = require("fast-xml-parser");

const app = express();
app.use(express.json({ limit: "10mb" })); // company logo comes in as a base64 data URL — the 100kb default was silently rejecting the whole settings save whenever a logo was attached

app.use(session({
  secret: process.env.SESSION_SECRET || "harbor-desk-dev-secret-change-me",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 12 } // 12 hours
}));

/* ---------------------------------------------------------------- */
/* AUTH — login / logout / current user                              */
/* ---------------------------------------------------------------- */
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE").get(username || "");
  if (!user || !user.active) return res.status(401).json({ error: "Invalid username or password" });
  if (user.locked) return res.status(403).json({ error: "This account is blocked after too many failed attempts. Please contact your admin to unlock it." });
  if (!bcrypt.compareSync(password || "", user.password_hash || "")) {
    const attempts = (user.failed_attempts || 0) + 1;
    if (attempts >= 5) {
      db.prepare("UPDATE users SET failed_attempts=?, locked=1 WHERE id=?").run(attempts, user.id);
      logActivity(req, "account_locked", `${user.username} — account blocked after ${attempts} failed login attempts`);
      return res.status(403).json({ error: "Too many wrong attempts — this account is now blocked. Please contact your admin to unlock it." });
    }
    db.prepare("UPDATE users SET failed_attempts=? WHERE id=?").run(attempts, user.id);
    return res.status(401).json({ error: "Invalid username or password" });
  }
  if (user.failed_attempts > 0) db.prepare("UPDATE users SET failed_attempts=0 WHERE id=?").run(user.id);
  req.session.user = { id: user.id, name: user.name, username: user.username, role: user.role, modules: user.modules.split(","), can_delete: !!user.can_delete, can_export: !!user.can_export, can_import: !!user.can_import, can_approve: !!user.can_approve, chatbot_only: !!user.chatbot_only };
  logActivity(req, "login", `${user.username} logged in`);
  res.json({ ok: true, user: req.session.user });
});
app.post("/api/logout", (req, res) => {
  logActivity(req, "logout", `${req.session.user ? req.session.user.username : "unknown"} logged out`);
  req.session.destroy(() => res.json({ ok: true }));
});
app.get("/api/me", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Not logged in" });
  res.json(req.session.user);
});

// A user can delete records only if their account has been granted that right (Admins always can)
function requireDelete(req, res, next) {
  const u = req.session.user;
  if (u && (u.can_delete || u.role === "Admin")) return next();
  return res.status(403).json({ error: "You don't have permission to delete records. Ask an admin to grant it." });
}
function requireApprove(req, res, next) {
  const u = req.session.user;
  if (u && (u.can_approve || u.role === "Admin")) return next();
  return res.status(403).json({ error: "You don't have permission to approve or un-approve Charges/Cost. Ask an admin to grant it." });
}

// Every other /api/* route requires a logged-in session
app.use("/api", (req, res, next) => {
  if (req.path === "/login" || req.path === "/logout" || req.path === "/me" || req.path === "/company-profile") return next();
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: "Not logged in" });
});

// Module-based authorization: a user can only call APIs for modules they've been given access to.
// Exception: read-only master/reference lists (vessels, parties, commodities, charge codes) are needed
// as dropdowns across every module, so GET requests to them are open to any logged-in user — only
// writes (create/edit/delete) require the owning module.
function moduleForPath(method, p) {
  const isRead = method === "GET";
  if (isRead && (p.startsWith("/vessels") || p.startsWith("/voyages") || p.startsWith("/parties") || p.startsWith("/commodities") || p.startsWith("/charge-codes") || p.startsWith("/ports"))) {
    return null;
  }
  if (p.startsWith("/jobs") || p.startsWith("/equipment") || p.startsWith("/charges") || p.startsWith("/containers") || p.startsWith("/costs")) return "job";
  if (p.startsWith("/charge-codes")) return "accounting";
  if (p.startsWith("/accounts") || p.startsWith("/account-groups") || p.startsWith("/vouchers") || p.startsWith("/voucher-types") || p.startsWith("/ledger") || p.startsWith("/receivables") || p.startsWith("/payables") || p.startsWith("/trial-balance") || p.startsWith("/bank-accounts") || p.startsWith("/credit-notes") || p.startsWith("/debit-notes")) return "accounting";
  if (p.startsWith("/vessels") || p.startsWith("/voyages") || p.startsWith("/parties") || p.startsWith("/users") || p.startsWith("/commodities") || p.startsWith("/ports") || p.startsWith("/settings") || p.startsWith("/opening-balances") || p.startsWith("/activity-logs") || p.startsWith("/email-logs") || p.startsWith("/vessel-campaigns")) return "admin";
  if (p.startsWith("/reports") || p.startsWith("/edi")) return "reports";
  if (p.startsWith("/chatbot")) return "chatbot";
  return null; // /login, /logout, /me and anything unlisted stay open to any logged-in user
}
app.use("/api", (req, res, next) => {
  const mod = moduleForPath(req.method, req.path);
  if (!mod) return next();
  if (req.session.user.modules.includes(mod)) return next();
  // Chatbot-access users can't open the Reports/Accounting pages themselves, but the chatbot needs to
  // read (never write) the same report/receivables/payables data to answer questions with real numbers.
  if (req.session.user.modules.includes("chatbot") && req.method === "GET" &&
    (req.path.startsWith("/reports") || req.path.startsWith("/edi") || req.path.startsWith("/receivables") || req.path.startsWith("/payables") || req.path.startsWith("/trial-balance"))) {
    return next();
  }
  return res.status(403).json({ error: "You don't have access to this module" });
});

// Users restricted to chatbot-only access can never open any other page — bounce them straight back.
app.use((req, res, next) => {
  if (req.path.startsWith("/api/") || req.path.startsWith("/css/") || req.path.startsWith("/js/")) return next();
  const u = req.session.user;
  if (u && u.chatbot_only && req.path !== "/chatbot.html") return res.redirect("/chatbot.html");
  next();
});

// Every page except the login page itself requires a logged-in session
app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) return next();
  if (req.path === "/login.html" || req.path.startsWith("/css/") || req.path.startsWith("/js/")) return next();
  if (req.session && req.session.user) return next();
  return res.redirect("/login.html");
});

app.use(express.static(path.join(__dirname, "public")));

const SIZE_TYPES = ["20SD","20RF","20OT","20GO","20TK","20FR","20BK","40SD","40HC","40RF","40FR","40OT"];

// Rough size/type -> ISO 6346 container type code mapping used by the EDI format.
// Adjust codes here if your carrier/port requires different ISO codes.
const ISO_TYPE_MAP = {
  "20SD":"22G1", "20RF":"22R1", "20OT":"22U1", "20GO":"22U1",
  "20TK":"22T1", "20FR":"22P1", "20BK":"22B1",
  "40SD":"42G1", "40HC":"45G1", "40RF":"42R1", "40FR":"42P1", "40OT":"42U1",
};
const ISO_TYPE_MAP_REVERSE = Object.fromEntries(Object.entries(ISO_TYPE_MAP).map(([k,v])=>[v,k]));
function isoForSize(size){ return ISO_TYPE_MAP[size] || "22G1"; }
function sizeForIso(iso){ return ISO_TYPE_MAP_REVERSE[iso] || "20SD"; }
function ymd(dateStr){ // "2026-09-11" -> "20260911"
  if (!dateStr) return "";
  return String(dateStr).replace(/-/g, "").slice(0,8);
}
function dashDate(ymdStr){ // "20260911" -> "2026-09-11"
  const s = String(ymdStr || "");
  if (s.length !== 8) return "";
  return `${s.slice(0,4)}-${s.slice(4,6)}-${s.slice(6,8)}`;
}
function xmlEscape(s){
  return String(s ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

/* ---------------------------------------------------------------- */
/* Helpers                                                           */
/* ---------------------------------------------------------------- */
// ---- Settings (financial year, SMTP config) ----
function getSetting(key, fallback) {
  const row = db.prepare("SELECT value FROM settings WHERE key=?").get(key);
  return row ? row.value : fallback;
}
function setSetting(key, value) {
  const exists = db.prepare("SELECT key FROM settings WHERE key=?").get(key);
  if (exists) db.prepare("UPDATE settings SET value=? WHERE key=?").run(value, key);
  else db.prepare("INSERT INTO settings (key, value) VALUES (?,?)").run(key, value);
}

// ---- Activity log ----
function logActivity(req, action, details) {
  const u = req.session && req.session.user;
  db.prepare("INSERT INTO activity_logs (user_id, username, action, details) VALUES (?,?,?,?)")
    .run(u ? u.id : null, u ? u.username : "system", action, details || "");
}

async function sendMail(req, { to, subject, html, relatedType, relatedRef }) {
  const u = req.session && req.session.user;
  const host = getSetting("smtp_host", "");
  const port = Number(getSetting("smtp_port", "587"));
  const secure = getSetting("smtp_secure", "false") === "true";
  const user = getSetting("smtp_user", "");
  const pass = getSetting("smtp_pass", "");
  const from = getSetting("smtp_from", user);

  const logResult = (status, error) => {
    db.prepare(`INSERT INTO email_logs (sent_by_user_id, sent_by_username, to_email, subject, related_type, related_ref, status, error)
      VALUES (?,?,?,?,?,?,?,?)`)
      .run(u ? u.id : null, u ? u.username : "system", to, subject, relatedType || "", relatedRef || "", status, error || "");
  };

  if (!host || !user || !pass) {
    logResult("failed", "SMTP is not configured yet — set it up under Admin → Settings");
    throw new Error("SMTP is not configured yet — set it up under Admin → Settings");
  }
  if (!to) {
    logResult("failed", "This party has no email address on file");
    throw new Error("This party has no email address on file — add one under Customers & Vendors");
  }

  try {
    const transporter = nodemailer.createTransport({ host, port, secure, auth: { user, pass } });
    await transporter.sendMail({ from: from || user, to, subject, html });
    logResult("sent", null);
    logActivity(req, "email_sent", `Emailed "${subject}" to ${to}`);
  } catch (e) {
    logResult("failed", e.message);
    throw new Error("Failed to send email: " + e.message);
  }
}

// ---- Vessel Schedule marketing emails: helpers ----
function parseEmails(str) {
  return Array.from(new Set(
    (str || "")
      .split(/[\n,;]+/)
      .map(s => s.trim())
      .filter(s => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s))
  ));
}

function campaignWithMeta(c) {
  if (!c) return c;
  const rows = db.prepare("SELECT status, COUNT(*) n FROM email_logs WHERE related_type='vessel_schedule' AND related_ref=? GROUP BY status").all(String(c.id));
  const counts = { sent: 0, failed: 0 };
  rows.forEach(r => counts[r.status] = r.n);
  return {
    ...c,
    send_times: JSON.parse(c.send_times || "[]"),
    last_sent_times: JSON.parse(c.last_sent_times || "[]"),
    pol_list: JSON.parse(c.pol_list || "[]"),
    pod_list: JSON.parse(c.pod_list || "[]"),
    sent_count: counts.sent, failed_count: counts.failed
  };
}

// Normalizes whatever the client sent for pol_list/pod_list into a clean [{port, eta}] array.
function cleanPortEtaList(raw) {
  if (!Array.isArray(raw)) return [];
  return raw
    .map(r => ({ port: String((r && r.port) || "").trim(), eta: String((r && r.eta) || "").trim() }))
    .filter(r => r.port);
}

// Sends ONE email (To/Cc/Bcc all set on a single message, as configured on the campaign) via the
// SMTP account configured under Admin -> Settings (works with Outlook/Office365 SMTP too), then logs
// a per-address delivery row in email_logs using nodemailer's accepted/rejected result.
async function sendCampaignBlast(campaign, byUsername, byUserId) {
  const host = getSetting("smtp_host", "");
  const port = Number(getSetting("smtp_port", "587"));
  const secure = getSetting("smtp_secure", "false") === "true";
  const user = getSetting("smtp_user", "");
  const pass = getSetting("smtp_pass", "");
  const from = getSetting("smtp_from", user) || user;
  if (!host || !user || !pass) throw new Error("SMTP is not configured yet — set it up under Admin → Settings");

  const toList = parseEmails(campaign.to_list);
  const ccList = parseEmails(campaign.cc_list);
  const bccList = parseEmails(campaign.bcc_list);
  if (!toList.length) throw new Error("This schedule has no valid email in the To list");

  const polRows = (JSON.parse(campaign.pol_list || "[]")).map(p => `<tr><td style="padding:3px 12px 3px 0;color:#5B6B78;">POL</td><td style="padding:3px 0;">${xmlEscape(p.port)}</td><td style="padding:3px 0 3px 12px;color:#5B6B78;">ETA</td><td style="padding:3px 0;">${xmlEscape(p.eta || "—")}</td></tr>`).join("");
  const podRows = (JSON.parse(campaign.pod_list || "[]")).map(p => `<tr><td style="padding:3px 12px 3px 0;color:#5B6B78;">POD</td><td style="padding:3px 0;">${xmlEscape(p.port)}</td><td style="padding:3px 0 3px 12px;color:#5B6B78;">ETA</td><td style="padding:3px 0;">${xmlEscape(p.eta || "—")}</td></tr>`).join("");
  const html = `<div style="font-family:sans-serif;font-size:14px;color:#1C2A36;">
    <div style="white-space:pre-line;margin-bottom:14px;">${xmlEscape(campaign.message || "")}</div>
    <table style="border-collapse:collapse;font-size:13px;">
      <tr><td style="padding:3px 12px 3px 0;color:#5B6B78;">Vessel</td><td colspan="3" style="padding:3px 0;font-weight:600;">${xmlEscape(campaign.vessel_name)}</td></tr>
      <tr><td style="padding:3px 12px 3px 0;color:#5B6B78;">Voyage</td><td colspan="3" style="padding:3px 0;font-weight:600;">${xmlEscape(campaign.voyage_no)}</td></tr>
      ${polRows || `<tr><td style="padding:3px 12px 3px 0;color:#5B6B78;">POL</td><td colspan="3" style="padding:3px 0;">—</td></tr>`}
      ${podRows || `<tr><td style="padding:3px 12px 3px 0;color:#5B6B78;">POD</td><td colspan="3" style="padding:3px 0;">—</td></tr>`}
      <tr><td style="padding:3px 12px 3px 0;color:#5B6B78;">ETD</td><td colspan="3" style="padding:3px 0;">${xmlEscape(campaign.etd || "—")}</td></tr>
    </table></div>`;

  const transporter = nodemailer.createTransport({ host, port, secure, auth: { user, pass } });
  const ins = db.prepare(`INSERT INTO email_logs (sent_by_user_id, sent_by_username, to_email, subject, related_type, related_ref, status, error) VALUES (?,?,?,?,?,?,?,?)`);
  const allAddrs = [...toList, ...ccList, ...bccList];

  let result;
  try {
    result = await transporter.sendMail({
      from, to: toList.join(","),
      cc: ccList.length ? ccList.join(",") : undefined,
      bcc: bccList.length ? bccList.join(",") : undefined,
      subject: campaign.subject, html
    });
  } catch (e) {
    allAddrs.forEach(addr => ins.run(byUserId, byUsername, addr, campaign.subject, "vessel_schedule", String(campaign.id), "failed", e.message));
    throw new Error("Failed to send: " + e.message);
  }
  const rejected = new Set((result.rejected || []).map(a => String(a.address || a).toLowerCase()));
  let sentN = 0, failN = 0;
  allAddrs.forEach(addr => {
    const ok = !rejected.has(addr.toLowerCase());
    ins.run(byUserId, byUsername, addr, campaign.subject, "vessel_schedule", String(campaign.id), ok ? "sent" : "failed", ok ? null : "Rejected by mail server");
    ok ? sentN++ : failN++;
  });
  db.prepare("UPDATE vessel_campaigns SET recipient_count=? WHERE id=?").run(toList.length, campaign.id);
  return { total: allAddrs.length, sent: sentN, failed: failN };
}

// Background scheduler: every minute, checks every "running" vessel-schedule campaign and fires it
// if the current HH:MM matches one of its configured send times and it hasn't already fired that
// exact slot today. This runs as long as the Node process (server.js) itself keeps running.
async function runScheduledCampaigns() {
  const now = new Date();
  const nowHM = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;
  const today = now.toISOString().slice(0, 10);
  const running = db.prepare("SELECT * FROM vessel_campaigns WHERE is_running=1").all();
  for (const c of running) {
    if (!c.schedule_start_date || today < c.schedule_start_date) continue;
    const times = JSON.parse(c.send_times || "[]");
    if (!times.includes(nowHM)) continue;
    const sentToday = c.last_sent_date === today ? JSON.parse(c.last_sent_times || "[]") : [];
    if (sentToday.includes(nowHM)) continue;
    try {
      const r = await sendCampaignBlast(c, "scheduler", null);
      sentToday.push(nowHM);
      db.prepare("UPDATE vessel_campaigns SET last_sent_date=?, last_sent_times=? WHERE id=?").run(today, JSON.stringify(sentToday), c.id);
      db.prepare("INSERT INTO activity_logs (user_id, username, action, details) VALUES (NULL,'scheduler','vessel_campaign_auto_sent',?)")
        .run(`Auto-sent vessel schedule email #${c.id} (${c.subject}) at ${nowHM} — ${r.sent} sent, ${r.failed} failed`);
    } catch (e) {
      db.prepare("INSERT INTO activity_logs (user_id, username, action, details) VALUES (NULL,'scheduler','vessel_campaign_auto_failed',?)")
        .run(`Auto-send failed for vessel schedule email #${c.id}: ${e.message}`);
    }
  }
}

// Shared sequential numbering, one independent counter per prefix per financial year — e.g. EXP-00001/26.
// The "year" used comes from the admin-configurable Financial Year setting, not the system clock.
// Party codes use no year: P-0001.
function currentFY() { return getSetting("financial_year", new Date().getFullYear().toString().slice(-2)); }
function nextSeq(seriesKey, prefix, pad, withYear) {
  const yy = currentFY();
  const key = withYear ? `${seriesKey}-${yy}` : seriesKey;
  const row = db.prepare("SELECT last_no FROM job_sequences WHERE year=?").get(key);
  const next = row ? row.last_no + 1 : 1;
  if (row) db.prepare("UPDATE job_sequences SET last_no=? WHERE year=?").run(next, key);
  else db.prepare("INSERT INTO job_sequences (year, last_no) VALUES (?,?)").run(key, next);
  const padded = String(next).padStart(pad, "0");
  return withYear ? `${prefix}-${padded}/${yy}` : `${prefix}-${padded}`;
}
function jobNoSeed(direction) {
  return direction === "Import" ? nextSeq("JOB-IMP", "IMP", 5, true) : nextSeq("JOB-EXP", "EXP", 5, true);
}
function txnSeed() { return nextSeq("INV", "INV", 5, true); } // fallback / legacy
function txnSeedForDirection(direction) {
  const prefix = String(direction || "").toLowerCase() === "import" ? "IMPINV" : "EXPINV";
  return nextSeq(prefix, prefix, 5, true);
}
function billNoSeed() { return nextSeq("BILL", "BILL", 5, true); }
function partyCodeSeed() { return nextSeq("PARTY", "P", 4, false); }
const MANUAL_VOUCHER_TYPES = ["CPV", "CRV", "BPV", "BRV", "JV"]; // Cash Payment/Receipt, Bank Payment/Receipt, Journal Voucher
function voucherNoFor(source) {
  const prefix = { invoice: "JV", receipt: "RCPT", bill: "JV", payment: "PV", manual: "JV" }[source] || "JV";
  return nextSeq(prefix, prefix, 4, true);
}
function postVoucher({ date, narration, source, lines, voucherType, paymentMode, referenceNo }) {
  const no = voucherType && MANUAL_VOUCHER_TYPES.includes(voucherType)
    ? nextSeq(voucherType, voucherType, 4, true)
    : voucherNoFor(source);
  const info = db.prepare("INSERT INTO vouchers (no, date, narration, source, payment_mode, reference_no) VALUES (?,?,?,?,?,?)")
    .run(no, date, narration, source, paymentMode || null, referenceNo || null);
  const voucherId = info.lastInsertRowid;
  const insLine = db.prepare("INSERT INTO voucher_lines (voucher_id, account_code, debit, credit) VALUES (?,?,?,?)");
  lines.forEach(l => insLine.run(voucherId, l.account, l.debit || 0, l.credit || 0));
  return { id: voucherId, no };
}
function accountBalance(code) {
  const row = db.prepare(`
    SELECT COALESCE(SUM(debit),0) dr, COALESCE(SUM(credit),0) cr
    FROM voucher_lines WHERE account_code = ?`).get(code);
  return { dr: row.dr, cr: row.cr, net: row.dr - row.cr };
}
function equipmentSizesForJob(jobId) {
  const rows = db.prepare("SELECT size, qty FROM job_equipment WHERE job_id=?").all(jobId);
  const sizes = {};
  rows.forEach(r => { if (r.qty > 0) sizes[r.size] = (sizes[r.size] || 0) + r.qty; });
  return sizes;
}
function chargeLinesForJob(jobId) {
  const sizes = equipmentSizesForJob(jobId);
  const rows = db.prepare("SELECT * FROM job_charges WHERE job_id=?").all(jobId);
  return rows.map(ch => {
    const autoQty = sizes[ch.size] || 0;
    const qty = (ch.qty_override !== null && ch.qty_override !== undefined) ? ch.qty_override : autoQty;
    const amt = qty * ch.rate;
    const rate = ch.exchange_rate || 1;
    return { ...ch, qty, auto_qty: autoQty, amt, base_amt: Math.round(amt * rate * 100) / 100 };
  });
}
// A bill can be linked to a job two ways — directly (ap_bills.job_id) or via the ap_bill_jobs join
// table — and the same bill sometimes ends up linked both ways. UNION de-duplicates so each bill is
// only counted once no matter which link(s) it has.
function billsForJobIds(jobIds) {
  if (!jobIds.length) return [];
  const ph = jobIds.map(()=>'?').join(',');
  return db.prepare(`
    SELECT b.* FROM ap_bills b WHERE b.job_id IN (${ph})
    UNION
    SELECT b.* FROM ap_bills b JOIN ap_bill_jobs j ON j.bill_id=b.id WHERE j.job_id IN (${ph})`).all(...jobIds, ...jobIds);
}
function costForJobIds(jobIds) { return billsForJobIds(jobIds).reduce((s, b) => s + b.amount, 0); }
function costPaidForJobIds(jobIds) { return billsForJobIds(jobIds).reduce((s, b) => s + b.settled_amount, 0); }
function outstandingCostForJobIds(jobIds) { return billsForJobIds(jobIds).reduce((s, b) => s + (b.amount - b.settled_amount), 0); }
// AED-converted cost, for reports (P&L) that need to add cost to AED-denominated revenue.
function baseCostForJobIds(jobIds) { return billsForJobIds(jobIds).reduce((s, b) => s + (b.base_amount || b.amount), 0); }

function jobSummary(job) {
  const invoice = db.prepare("SELECT * FROM invoices WHERE job_id=? ORDER BY id DESC LIMIT 1").get(job.id);
  const invoiceCount = db.prepare("SELECT COUNT(*) c FROM invoices WHERE job_id=?").get(job.id).c;
  const bl = db.prepare("SELECT * FROM job_bl WHERE job_id=?").get(job.id);
  const vessel = job.vessel_id ? db.prepare("SELECT * FROM vessels WHERE id=?").get(job.vessel_id) : null;
  const voyage = job.voyage_id ? db.prepare("SELECT * FROM voyages WHERE id=?").get(job.voyage_id) : null;
  const costTotal = costForJobIds([job.id]);
  const costPaid = costPaidForJobIds([job.id]);
  return {
    ...job,
    vessel_name: vessel ? vessel.name : null,
    voyage_no: voyage ? voyage.no : null,
    invoice: invoice || null,
    invoice_count: invoiceCount,
    bl: bl || null,
    cost_total: costTotal,
    cost_paid: costPaid
  };
}

/* ---------------------------------------------------------------- */
/* JOBS  (Booking Info)                                               */
/* ---------------------------------------------------------------- */
app.get("/api/jobs", (req, res) => {
  const jobs = db.prepare("SELECT * FROM jobs ORDER BY id DESC").all();
  res.json(jobs.map(jobSummary));
});

app.post("/api/jobs", (req, res) => {
  const direction = req.body.direction === "Import" ? "Import" : "Export";
  const jobNo = jobNoSeed(direction);
  const info = db.prepare(`INSERT INTO jobs (job_no, job_date, direction) VALUES (?, date('now'), ?)`).run(jobNo, direction);
  const job = db.prepare("SELECT * FROM jobs WHERE id=?").get(info.lastInsertRowid);
  db.prepare("INSERT INTO job_bl (job_id, hbl) VALUES (?,?)").run(job.id, jobNo);
  logActivity(req, "job_created", `Job ${jobNo} (${direction}) created`);
  res.json(jobSummary(job));
});

app.get("/api/jobs/:id", (req, res) => {
  const job = db.prepare("SELECT * FROM jobs WHERE id=?").get(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found" });
  res.json(jobSummary(job));
});

// Look a job up by its serial/job number (e.g. EXP-00001/26) — used by the "Search by Job #" box on every job form.
app.get("/api/jobs/by-no/:no", (req, res) => {
  const job = db.prepare("SELECT * FROM jobs WHERE job_no = ? COLLATE NOCASE").get(req.params.no.trim());
  if (!job) return res.status(404).json({ error: `No job found with number "${req.params.no}"` });
  res.json(jobSummary(job));
});

app.delete("/api/jobs/:id", requireDelete, (req, res) => {
  const job = db.prepare("SELECT * FROM jobs WHERE id=?").get(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found" });
  const reason = (req.body && req.body.reason || "").trim();
  if (!reason) return res.status(400).json({ error: "A reason/comment is required to delete a job." });
  // vendor bills reference the job but aren't owned by it — detach rather than cascade-delete financial records
  db.prepare("UPDATE ap_bills SET job_id=NULL WHERE job_id=?").run(req.params.id);
  db.prepare("DELETE FROM jobs WHERE id=?").run(req.params.id);
  logActivity(req, "job_deleted", `Job ${job.job_no} deleted — reason: ${reason}`);
  res.json({ ok: true });
});

function partyHasRole(name, roleColumn) {
  if (!name) return true;
  return !!db.prepare(`SELECT id FROM parties WHERE name = ? COLLATE NOCASE AND ${roleColumn}=1`).get(name);
}
// Any customer/vendor already added should be selectable everywhere. Rather than blocking the save
// because a role checkbox wasn't ticked under Customers & Vendors, silently grant that role the first
// time the party is used in that slot — this is what keeps every added party visible in every dropdown.
function ensurePartyRole(name, roleColumn) {
  if (!name) return;
  const p = db.prepare(`SELECT id, ${roleColumn} as has FROM parties WHERE name = ? COLLATE NOCASE`).get(name);
  if (p && !p.has) db.prepare(`UPDATE parties SET ${roleColumn}=1 WHERE id=?`).run(p.id);
}
// A party that is ONLY a vendor (never tagged Client) can't be picked as a job's Client — vendors and
// customers are kept as distinct identities, unlike Shipper/Consignee which any party can fill.
function assertNotVendorOnly(name) {
  if (!name) return null;
  const p = db.prepare("SELECT is_client, is_vendor FROM parties WHERE name = ? COLLATE NOCASE").get(name);
  if (p && p.is_vendor && !p.is_client) {
    return `"${name}" is tagged as a Vendor — vendors cannot be selected as a Client. Tag them as a Client under Customers & Vendors first if that's intended.`;
  }
  return null;
}
function duplicateTrnOrLicense(trn, tradeLicense, excludeId) {
  if (trn) {
    const row = excludeId
      ? db.prepare("SELECT name FROM parties WHERE trn = ? AND id != ?").get(trn, excludeId)
      : db.prepare("SELECT name FROM parties WHERE trn = ?").get(trn);
    if (row) return `TRN "${trn}" is already used by "${row.name}" — TRN must be unique.`;
  }
  if (tradeLicense) {
    const row = excludeId
      ? db.prepare("SELECT name FROM parties WHERE trade_license = ? AND id != ?").get(tradeLicense, excludeId)
      : db.prepare("SELECT name FROM parties WHERE trade_license = ?").get(tradeLicense);
    if (row) return `Trade License "${tradeLicense}" is already used by "${row.name}" — it must be unique.`;
  }
  return null;
}

app.post("/api/jobs/:id/renumber", (req, res) => {
  const job = db.prepare("SELECT * FROM jobs WHERE id=?").get(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found" });
  if (db.prepare("SELECT id FROM invoices WHERE job_id=?").get(job.id)) {
    return res.status(400).json({ error: "Can't renumber — this job already has an invoice" });
  }
  const direction = req.body.direction === "Import" ? "Import" : "Export";
  const newNo = jobNoSeed(direction);
  db.prepare("UPDATE jobs SET job_no=?, direction=? WHERE id=?").run(newNo, direction, job.id);
  const bl = db.prepare("SELECT * FROM job_bl WHERE job_id=?").get(job.id);
  if (bl && bl.hbl === job.job_no) db.prepare("UPDATE job_bl SET hbl=? WHERE job_id=?").run(newNo, job.id);
  logActivity(req, "job_renumbered", `Job ${job.job_no} renumbered to ${newNo}`);
  res.json(jobSummary(db.prepare("SELECT * FROM jobs WHERE id=?").get(job.id)));
});

app.put("/api/jobs/:id", (req, res) => {
  const f = req.body;
  const existingJob = db.prepare("SELECT booking_approved FROM jobs WHERE id=?").get(req.params.id);
  if (!existingJob) return res.status(404).json({ error: "Job not found" });
  if (existingJob.booking_approved) {
    return res.status(400).json({ error: "Booking Info is approved and locked — click Un-approve Booking first if you need to change it." });
  }

  // Any party already added under Customers & Vendors can be picked here — we tag the role
  // automatically rather than bouncing the save back. Exception: a Vendor-only party cannot become a Client.
  const vendorClashErr = assertNotVendorOnly(f.client);
  if (vendorClashErr) return res.status(400).json({ error: vendorClashErr });
  ensurePartyRole(f.client, "is_client");
  ensurePartyRole(f.shipper, "is_shipper");
  ensurePartyRole(f.consignee, "is_consignee");
  if (f.pol && !findPortByName(f.pol)) {
    return res.status(400).json({ error: `"${f.pol}" is not a recognised port — pick one from the Port of Loading list` });
  }
  if (f.pod && !findPortByName(f.pod)) {
    return res.status(400).json({ error: `"${f.pod}" is not a recognised port — pick one from the Port of Discharge list` });
  }
  if (f.pol && f.pod && f.pol.trim().toUpperCase() === f.pod.trim().toUpperCase()) {
    return res.status(400).json({ error: "This port is already used as Port of Loading — please select a different port for Port of Discharge" });
  }
  if (f.final_dest && !findPortByName(f.final_dest)) {
    return res.status(400).json({ error: `"${f.final_dest}" is not a recognised port — pick one from the list, or leave blank to use Port of Discharge` });
  }
  if (f.voyage_id) {
    const voy = db.prepare("SELECT closed FROM voyages WHERE id=?").get(f.voyage_id);
    const cur = db.prepare("SELECT voyage_id FROM jobs WHERE id=?").get(req.params.id);
    if (voy && voy.closed && (!cur || cur.voyage_id != f.voyage_id)) {
      return res.status(400).json({ error: "This voyage is financially closed — new jobs cannot be added to it" });
    }
  }

  let cutOff = null;
  if (f.voyage_id) {
    const voy = db.prepare("SELECT cut_off FROM voyages WHERE id=?").get(f.voyage_id);
    cutOff = voy ? voy.cut_off : null;
  }

  db.prepare(`
    UPDATE jobs SET job_date=?, cost_center=?, freight_type=?, sales_rep=?, client=?, shipper=?, consignee=?,
      commodity=?, pol=?, pod=?, final_dest=?, vessel_id=?, voyage_id=?, etd=?, eta=?, direction=?, cut_off=?, booking_saved=1
    WHERE id=?`)
    .run(f.job_date, f.cost_center, f.freight_type, f.sales_rep, f.client, f.shipper, f.consignee,
         f.commodity, f.pol, f.pod, f.final_dest, f.vessel_id || null, f.voyage_id || null, f.etd, f.eta,
         f.direction === "Import" ? "Import" : "Export", cutOff, req.params.id);
  const job = db.prepare("SELECT * FROM jobs WHERE id=?").get(req.params.id);
  res.json(jobSummary(job));
});

app.post("/api/jobs/:id/approve-booking", (req, res) => {
  db.prepare("UPDATE jobs SET booking_approved=1 WHERE id=?").run(req.params.id);
  logActivity(req, "booking_approved", `Job ${req.params.id} — booking approved`);
  res.json(jobSummary(db.prepare("SELECT * FROM jobs WHERE id=?").get(req.params.id)));
});
// Booking must be un-approved before its fields can be edited again — mirrors the Charges
// approve/un-approve pattern, so an approved booking can't drift after downstream work (charges,
// bills) has already started referencing it, without a deliberate un-lock step first.
app.post("/api/jobs/:id/unapprove-booking", (req, res) => {
  db.prepare("UPDATE jobs SET booking_approved=0 WHERE id=?").run(req.params.id);
  logActivity(req, "booking_unapproved", `Job ${req.params.id} — booking un-approved`);
  res.json(jobSummary(db.prepare("SELECT * FROM jobs WHERE id=?").get(req.params.id)));
});

app.post("/api/jobs/:id/approve-charges", requireApprove, (req, res) => {
  const chargeCount = db.prepare("SELECT COUNT(*) c FROM job_charges WHERE job_id=?").get(req.params.id).c;
  if (chargeCount === 0) return res.status(400).json({ error: "Add charges first — there's nothing to approve yet." });
  db.prepare("UPDATE jobs SET charges_approved=1, job_approved=1 WHERE id=?").run(req.params.id);
  logActivity(req, "charges_approved", `Job ${req.params.id} — charges approved`);
  res.json(jobSummary(db.prepare("SELECT * FROM jobs WHERE id=?").get(req.params.id)));
});

app.post("/api/jobs/:id/unapprove-charges", requireApprove, (req, res) => {
  db.prepare("UPDATE jobs SET charges_approved=0, job_approved=0 WHERE id=?").run(req.params.id);
  logActivity(req, "charges_unapproved", `Job ${req.params.id} — charges un-approved`);
  res.json(jobSummary(db.prepare("SELECT * FROM jobs WHERE id=?").get(req.params.id)));
});

/* ---- Equipment ---- */
app.get("/api/jobs/:id/equipment", (req, res) => {
  res.json(db.prepare("SELECT * FROM job_equipment WHERE job_id=?").all(req.params.id));
});
function equipmentSizeTaken(jobId, size, excludeRowId) {
  const row = excludeRowId
    ? db.prepare("SELECT id FROM job_equipment WHERE job_id=? AND size=? AND id!=?").get(jobId, size, excludeRowId)
    : db.prepare("SELECT id FROM job_equipment WHERE job_id=? AND size=?").get(jobId, size);
  return !!row;
}
app.post("/api/jobs/:id/equipment", (req, res) => {
  const { size, qty, dg } = req.body;
  const finalSize = size || "20SD";
  if (equipmentSizeTaken(req.params.id, finalSize)) {
    return res.status(400).json({ error: `${finalSize} is already added to this job — edit the existing row instead of adding a duplicate.` });
  }
  const info = db.prepare("INSERT INTO job_equipment (job_id, size, qty, dg) VALUES (?,?,?,?)")
    .run(req.params.id, finalSize, qty || 0, dg || "Non DG");
  res.json(db.prepare("SELECT * FROM job_equipment WHERE id=?").get(info.lastInsertRowid));
});
app.put("/api/equipment/:rowId", (req, res) => {
  const { size, qty, dg } = req.body;
  const row = db.prepare("SELECT * FROM job_equipment WHERE id=?").get(req.params.rowId);
  if (!row) return res.status(404).json({ error: "Equipment row not found" });
  if (equipmentSizeTaken(row.job_id, size, req.params.rowId)) {
    return res.status(400).json({ error: `${size} is already added to this job — it's already on another row.` });
  }
  db.prepare("UPDATE job_equipment SET size=?, qty=?, dg=? WHERE id=?").run(size, qty, dg, req.params.rowId);
  res.json(db.prepare("SELECT * FROM job_equipment WHERE id=?").get(req.params.rowId));
});
app.delete("/api/equipment/:rowId", requireDelete, (req, res) => {
  db.prepare("DELETE FROM job_equipment WHERE id=?").run(req.params.rowId);
  res.json({ ok: true });
});

/* ---- Charges ---- */
app.get("/api/jobs/:id/charges", (req, res) => {
  res.json(chargeLinesForJob(req.params.id));
});
app.post("/api/jobs/:id/charges", (req, res) => {
  const job = db.prepare("SELECT * FROM jobs WHERE id=?").get(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found" });
  if (!job.booking_saved) return res.status(400).json({ error: "Save Booking Info first — charges can't be added until the booking has been saved." });
  const { code, size, rate } = req.body;
  const currency = req.body.currency || "AED";
  const exchange_rate = currency === "AED" ? 1 : Number(req.body.exchange_rate) || 1;
  const info = db.prepare("INSERT INTO job_charges (job_id, code, size, rate, currency, exchange_rate) VALUES (?,?,?,?,?,?)")
    .run(req.params.id, code || "SLOT", size, rate || 0, currency, exchange_rate);
  res.json({ id: info.lastInsertRowid });
});
app.put("/api/charges/:rowId", (req, res) => {
  const { code, size, rate } = req.body;
  const currency = req.body.currency || "AED";
  const exchange_rate = currency === "AED" ? 1 : Number(req.body.exchange_rate) || 1;
  if (currency !== "AED" && !req.body.exchange_rate) {
    return res.status(400).json({ error: `Enter the exchange rate for ${currency} → AED` });
  }
  // qty_override: null/undefined leaves it untouched (still whatever it was); pass null explicitly to
  // reset back to the Equipment-derived automatic quantity.
  const cur = db.prepare("SELECT qty_override FROM job_charges WHERE id=?").get(req.params.rowId);
  const qty_override = req.body.hasOwnProperty("qty_override")
    ? (req.body.qty_override === null || req.body.qty_override === "" ? null : Number(req.body.qty_override))
    : (cur ? cur.qty_override : null);
  db.prepare("UPDATE job_charges SET code=?, size=?, rate=?, currency=?, exchange_rate=?, qty_override=? WHERE id=?")
    .run(code, size, rate, currency, exchange_rate, qty_override, req.params.rowId);
  res.json({ ok: true });
});
app.delete("/api/charges/:rowId", requireDelete, (req, res) => {
  db.prepare("DELETE FROM job_charges WHERE id=?").run(req.params.rowId);
  res.json({ ok: true });
});

/* ---- B/L + Containers ---- */
app.get("/api/jobs/:id/bl", (req, res) => {
  res.json(db.prepare("SELECT * FROM job_bl WHERE job_id=?").get(req.params.id) || {});
});
app.put("/api/jobs/:id/bl", (req, res) => {
  const { hbl, mbl, release_status, handover_type, place_of_receipt, place_of_delivery, weight_unit,
    delivery_agent, no_of_originals, agent_stamp, marks_and_numbers, no_of_packages, goods_description } = req.body;
  const hide_freight_type = req.body.hide_freight_type ? 1 : 0;
  const exists = db.prepare("SELECT job_id FROM job_bl WHERE job_id=?").get(req.params.id);
  if (exists) {
    db.prepare(`UPDATE job_bl SET hbl=?, mbl=?, release_status=?, handover_type=?, place_of_receipt=?, place_of_delivery=?,
        weight_unit=?, hide_freight_type=?, delivery_agent=?, no_of_originals=?, agent_stamp=?, marks_and_numbers=?,
        no_of_packages=?, goods_description=? WHERE job_id=?`)
      .run(hbl, mbl, release_status, handover_type, place_of_receipt || "", place_of_delivery || "",
           weight_unit || "KGS", hide_freight_type, delivery_agent || "", no_of_originals || "", agent_stamp || "",
           marks_and_numbers || "", no_of_packages || "", goods_description || "", req.params.id);
  } else {
    db.prepare(`INSERT INTO job_bl (job_id, hbl, mbl, release_status, handover_type, place_of_receipt, place_of_delivery,
        weight_unit, hide_freight_type, delivery_agent, no_of_originals, agent_stamp, marks_and_numbers, no_of_packages, goods_description)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .run(req.params.id, hbl, mbl, release_status, handover_type, place_of_receipt || "", place_of_delivery || "",
           weight_unit || "KGS", hide_freight_type, delivery_agent || "", no_of_originals || "", agent_stamp || "",
           marks_and_numbers || "", no_of_packages || "", goods_description || "");
  }
  res.json(db.prepare("SELECT * FROM job_bl WHERE job_id=?").get(req.params.id));
});

// ISO 6346 shape: 4 letters (owner code + category) followed by 7 digits (serial + check digit) = 11 characters total.
const CONTAINER_NO_RE = /^[A-Z]{4}[0-9]{7}$/;
function containerNoDuplicate(no, excludeRowId) {
  if (!no) return false;
  const row = excludeRowId
    ? db.prepare("SELECT id FROM job_containers WHERE no = ? COLLATE NOCASE AND id!=?").get(no, excludeRowId)
    : db.prepare("SELECT id FROM job_containers WHERE no = ? COLLATE NOCASE").get(no);
  return !!row;
}
function validateContainerNo(no) {
  if (!no) return null; // blank allowed while the row is still being filled in
  const clean = no.trim().toUpperCase();
  if (!CONTAINER_NO_RE.test(clean)) {
    return `Container number "${no}" is invalid — it must be 11 characters: 4 letters followed by 7 digits (e.g. MSKU1234567)`;
  }
  return null;
}

app.get("/api/jobs/:id/containers", (req, res) => {
  res.json(db.prepare("SELECT * FROM job_containers WHERE job_id=?").all(req.params.id));
});
app.post("/api/jobs/:id/containers", (req, res) => {
  const { seal, size, weight, net_weight, measurement } = req.body;
  const no = (req.body.no || "").trim().toUpperCase();
  const formatErr = validateContainerNo(no);
  if (formatErr) return res.status(400).json({ error: formatErr });
  if (containerNoDuplicate(no)) return res.status(400).json({ error: `Container number "${no}" already exists — duplicate container numbers are not allowed.` });
  const info = db.prepare("INSERT INTO job_containers (job_id, no, seal, size, weight, net_weight, measurement) VALUES (?,?,?,?,?,?,?)")
    .run(req.params.id, no || "", seal || "", size || "20SD", weight || 0, net_weight || 0, measurement || 0);
  res.json(db.prepare("SELECT * FROM job_containers WHERE id=?").get(info.lastInsertRowid));
});
app.post("/api/jobs/:id/containers/bulk", (req, res) => {
  const rows = req.body.rows || [];
  const ins = db.prepare("INSERT INTO job_containers (job_id, no, seal, size, weight, net_weight, measurement) VALUES (?,?,?,?,?,?,?)");
  const accepted = [], rejected = [];
  const seenInBatch = new Set();
  rows.forEach(r => {
    const no = (r.no || "").trim().toUpperCase();
    const formatErr = validateContainerNo(no);
    if (formatErr) { rejected.push({ no: r.no, reason: formatErr }); return; }
    if (containerNoDuplicate(no) || seenInBatch.has(no)) { rejected.push({ no: r.no, reason: `Duplicate container number "${no}"` }); return; }
    seenInBatch.add(no);
    accepted.push({ ...r, no });
  });
  const tx = db.transaction((rows) => rows.forEach(r => ins.run(req.params.id, r.no, "", r.size, r.weight, r.net_weight || 0, r.measurement || 0)));
  tx(accepted);
  res.json({ containers: db.prepare("SELECT * FROM job_containers WHERE job_id=?").all(req.params.id), added: accepted.length, rejected });
});
app.delete("/api/containers/:rowId", requireDelete, (req, res) => {
  db.prepare("DELETE FROM job_containers WHERE id=?").run(req.params.rowId);
  res.json({ ok: true });
});
app.put("/api/containers/:rowId", (req, res) => {
  const { seal, size, weight, net_weight, measurement } = req.body;
  const no = (req.body.no || "").trim().toUpperCase();
  const formatErr = validateContainerNo(no);
  if (formatErr) return res.status(400).json({ error: formatErr });
  if (containerNoDuplicate(no, req.params.rowId)) return res.status(400).json({ error: `Container number "${no}" already exists — duplicate container numbers are not allowed.` });
  db.prepare("UPDATE job_containers SET no=?, seal=?, size=?, weight=?, net_weight=?, measurement=? WHERE id=?")
    .run(no, seal, size, weight, net_weight || 0, measurement || 0, req.params.rowId);
  res.json(db.prepare("SELECT * FROM job_containers WHERE id=?").get(req.params.rowId));
});

/* ---- Invoice (posts to Accounting) ---- */
app.get("/api/jobs/:id/invoices", (req, res) => {
  res.json(db.prepare("SELECT * FROM invoices WHERE job_id=? ORDER BY id DESC").all(req.params.id));
});
app.post("/api/jobs/:id/invoice", (req, res) => {
  const jobId = req.params.id;
  const job = db.prepare("SELECT * FROM jobs WHERE id=?").get(jobId);
  if (!job) return res.status(404).json({ error: "Job not found" });
  if (!job.booking_approved) return res.status(400).json({ error: "Please approve Booking Info first — invoices can't be generated for an unapproved booking" });
  if (!job.charges_approved) return res.status(400).json({ error: "Please approve Charges first — invoices can't be generated until Charges are approved." });
  const { date, currency, bank, vat_rate, vat_account, exchange_rate } = req.body;
  const lines = chargeLinesForJob(jobId);
  const subtotal = lines.reduce((s, l) => s + l.base_amt, 0); // AED-converted, so mixed-currency charge lines still balance in the ledger
  if (subtotal <= 0) return res.status(400).json({ error: "No charges to invoice" });

  const vatRate = Number(vat_rate || 0);
  const vatAmount = Math.round(subtotal * vatRate) / 100;
  const total = subtotal + vatAmount;
  const fxRate = Number(exchange_rate || 1) || 1;

  const txn = txnSeedForDirection(job.direction);
  db.prepare(`INSERT INTO invoices (job_id, txn, date, currency, bank, amount, vat_rate, vat_amount, vat_account, exchange_rate)
    VALUES (?,?,?,?,?,?,?,?,?,?)`)
    .run(jobId, txn, date, currency || "USD", bank || "", total, vatRate, vatAmount, vat_account || "2100", fxRate);

  const revenueSplit = {};
  lines.forEach(l => {
    const cc = db.prepare("SELECT account_code FROM charge_codes WHERE code=?").get(l.code);
    const acct = cc ? cc.account_code : "4000";
    revenueSplit[acct] = (revenueSplit[acct] || 0) + l.base_amt;
  });
  const jvLines = [{ account: "1000", debit: total, credit: 0 }];
  Object.entries(revenueSplit).forEach(([acct, amt]) => jvLines.push({ account: acct, debit: 0, credit: amt }));
  if (vatAmount > 0) jvLines.push({ account: vat_account || "2100", debit: 0, credit: vatAmount });
  postVoucher({ date, narration: `Sales invoice ${txn} — Job ${job.job_no} — ${job.client}`, source: "invoice", lines: jvLines });
  logActivity(req, "invoice_created", `Invoice ${txn} for Job ${job.job_no} — ${job.client} — ${total} (VAT ${vatAmount})`);

  res.json(db.prepare("SELECT * FROM invoices WHERE txn=?").get(txn));
});

// Edit an already-created invoice — date, currency, bank, VAT rate/account, exchange rate. The
// underlying charge lines aren't re-picked (those still come from the job's Charges), but changing
// the VAT rate changes the total, so any amount delta is posted as an adjustment voucher, same
// pattern as editing a vendor bill. Blocked once a receipt has been recorded against it.
app.put("/api/invoices/:id", (req, res) => {
  const inv = db.prepare("SELECT * FROM invoices WHERE id=?").get(req.params.id);
  if (!inv) return res.status(404).json({ error: "Invoice not found" });
  if (inv.settled_amount > 0) return res.status(400).json({ error: "This invoice already has a receipt recorded against it and can no longer be edited — reverse the receipt first if a correction is needed." });
  const job = db.prepare("SELECT * FROM jobs WHERE id=?").get(inv.job_id);
  const { date, currency, bank, vat_account } = req.body;
  const vatRate = req.body.vat_rate !== undefined ? Number(req.body.vat_rate) : inv.vat_rate;
  const fxRate = req.body.exchange_rate !== undefined ? (Number(req.body.exchange_rate) || 1) : inv.exchange_rate;

  const lines = chargeLinesForJob(inv.job_id);
  const subtotal = lines.reduce((s, l) => s + l.base_amt, 0);
  const vatAmount = Math.round(subtotal * vatRate) / 100;
  const newTotal = subtotal + vatAmount;
  const delta = Math.round((newTotal - inv.amount) * 100) / 100;

  db.prepare(`UPDATE invoices SET date=?, currency=?, bank=?, vat_rate=?, vat_amount=?, vat_account=?, exchange_rate=?, amount=? WHERE id=?`)
    .run(date ?? inv.date, currency ?? inv.currency, bank ?? inv.bank, vatRate, vatAmount, vat_account ?? inv.vat_account, fxRate, newTotal, inv.id);

  if (Math.abs(delta) > 0.004) {
    const vatAcct = vat_account ?? inv.vat_account ?? "2100";
    postVoucher({
      date: date || inv.date,
      narration: `Adjustment to invoice ${inv.txn} — ${job ? job.client : ""} (amount corrected)`,
      source: "invoice",
      lines: delta > 0
        ? [{ account: "1000", debit: delta, credit: 0 }, { account: vatAcct, debit: 0, credit: delta }]
        : [{ account: vatAcct, debit: -delta, credit: 0 }, { account: "1000", debit: 0, credit: -delta }]
    });
  }
  logActivity(req, "invoice_edited", `Invoice ${inv.txn} edited${Math.abs(delta) > 0.004 ? ` — amount adjusted by ${delta}` : ""}`);
  res.json(db.prepare("SELECT * FROM invoices WHERE id=?").get(inv.id));
});

app.post("/api/jobs/:id/invoice/email", async (req, res) => {
  const jobId = req.params.id;
  const job = db.prepare("SELECT * FROM jobs WHERE id=?").get(jobId);
  if (!job) return res.status(404).json({ error: "Job not found" });
  const invoice = req.body.invoice_id
    ? db.prepare("SELECT * FROM invoices WHERE id=? AND job_id=?").get(req.body.invoice_id, jobId)
    : db.prepare("SELECT * FROM invoices WHERE job_id=? ORDER BY id DESC LIMIT 1").get(jobId);
  if (!invoice) return res.status(400).json({ error: "This job has no saved invoice yet" });
  const client = findPartyByName(job.client);
  const to = (client && client.email) || "";
  const lines = chargeLinesForJob(jobId);
  const bl = db.prepare("SELECT * FROM job_bl WHERE job_id=?").get(jobId);

  const containers = db.prepare("SELECT * FROM job_containers WHERE job_id=?").all(jobId);
  const companyName = getSetting("company_name", "Harbor Desk Shipping LLC");
  const companyAddress = getSetting("company_address", "");
  const companyEmail = getSetting("company_email", "");
  const companyPhone = getSetting("company_phone", "");
  const companyLogo = getSetting("company_logo", "");
  const rowsHtml = lines.map(l => `<tr><td>${l.code}</td><td>${l.size}</td><td style="text-align:right;">${l.qty}</td><td style="text-align:right;">${l.rate.toFixed(2)}</td><td>${l.currency}</td><td style="text-align:right;">${l.amt.toFixed(2)}</td></tr>`).join("");
  const containerRowsHtml = containers.map(c => `<tr><td>${c.no||"—"}</td><td>${c.size}</td><td style="text-align:right;">${(c.weight||0).toFixed(2)}</td></tr>`).join("")
    || `<tr><td colspan="3">No containers on file</td></tr>`;
  const html = `
    <div style="font-family:Arial,sans-serif;color:#1C2A36;">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2px solid #1C2A36;padding-bottom:10px;margin-bottom:14px;">
        <div style="display:flex;align-items:center;gap:10px;">
          ${companyLogo ? `<img src="${companyLogo}" style="max-height:44px;max-width:120px;">` : ""}
          <h2 style="margin:0;">Tax Invoice — ${invoice.txn}</h2>
        </div>
        <div style="text-align:right;font-size:12px;">
          <div style="font-weight:700;">${companyName}</div>
          ${companyAddress ? `<div>${companyAddress}</div>` : ""}
          ${companyEmail ? `<div>${companyEmail}</div>` : ""}
          ${companyPhone ? `<div>${companyPhone}</div>` : ""}
        </div>
      </div>
      <p><b>Job #:</b> ${job.job_no}<br><b>HBL #:</b> ${bl ? bl.hbl : "—"}<br><b>Date:</b> ${invoice.date}</p>
      <table style="border-collapse:collapse;width:100%;font-size:13px;">
        <thead><tr style="background:#F0F2F4;"><th style="text-align:left;padding:6px;">Charge</th><th style="text-align:left;padding:6px;">Size</th><th style="text-align:right;padding:6px;">Qty</th><th style="text-align:right;padding:6px;">Rate</th><th style="text-align:left;padding:6px;">Ccy</th><th style="text-align:right;padding:6px;">Amount</th></tr></thead>
        <tbody>${rowsHtml}</tbody>
      </table>
      <p style="margin-top:14px;"><b>Net Amount: ${invoice.currency} ${(invoice.amount / (invoice.currency === "AED" ? 1 : (invoice.exchange_rate || 1))).toFixed(2)}</b></p>
      <h3 style="margin-top:16px;font-size:13px;">Container Details</h3>
      <table style="border-collapse:collapse;width:100%;font-size:13px;">
        <thead><tr style="background:#F0F2F4;"><th style="text-align:left;padding:6px;">Container #</th><th style="text-align:left;padding:6px;">Size</th><th style="text-align:right;padding:6px;">Gross Wt (kg)</th></tr></thead>
        <tbody>${containerRowsHtml}</tbody>
      </table>
      <p style="color:#5B6B78;font-size:12px;margin-top:10px;">Bank: ${invoice.bank || "—"}</p>
      <div style="border-top:1px solid #DBE1E7;margin-top:20px;padding-top:8px;font-size:11px;color:#5B6B78;text-align:center;">
        ${[companyName, companyAddress, companyEmail, companyPhone].filter(Boolean).join(" · ")}
      </div>
    </div>`;

  try {
    await sendMail(req, { to, subject: `Invoice ${invoice.txn} — Job ${job.job_no}`, html, relatedType: "invoice", relatedRef: invoice.txn });
    res.json({ ok: true, to });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

/* ---------------------------------------------------------------- */
/* ACCOUNTING                                                         */
/* ---------------------------------------------------------------- */
app.get("/api/accounts", (req, res) => {
  const accounts = db.prepare(`
    SELECT a.*, g.name group_name, p.name linked_party_name
    FROM accounts a
    LEFT JOIN account_groups g ON g.id = a.group_id
    LEFT JOIN parties p ON p.id = a.linked_party_id
    ORDER BY a.code`).all();
  const ccStmt = db.prepare("SELECT code, name FROM charge_codes WHERE account_code=?");
  res.json(accounts.map(a => ({ ...a, balance: accountBalance(a.code), used_by_charges: ccStmt.all(a.code) })));
});

/* ---- Account Groups (chart-of-accounts heads) ---- */
app.get("/api/account-groups", (req, res) => {
  res.json(db.prepare("SELECT * FROM account_groups ORDER BY prefix").all());
});
app.post("/api/account-groups", (req, res) => {
  const name = (req.body.name || "").trim();
  const { type } = req.body;
  const prefix = (req.body.prefix || "").trim();
  if (!name || !type || !prefix) return res.status(400).json({ error: "Group name, type and numbering prefix are all required" });
  if (!/^[0-9]{1,3}$/.test(prefix)) return res.status(400).json({ error: "Prefix should be 1–3 digits, e.g. \"12\"" });
  if (db.prepare("SELECT id FROM account_groups WHERE prefix=?").get(prefix)) {
    return res.status(400).json({ error: `Prefix "${prefix}" is already used by another group` });
  }
  const info = db.prepare("INSERT INTO account_groups (name, type, prefix) VALUES (?,?,?)").run(name, type, prefix);
  res.json(db.prepare("SELECT * FROM account_groups WHERE id=?").get(info.lastInsertRowid));
});
// Next free code under a group, e.g. prefix "10" -> "1001", "1002", ... shown live in the New Account form.
function nextCodeForGroup(groupId) {
  const group = db.prepare("SELECT * FROM account_groups WHERE id=?").get(groupId);
  if (!group) return null;
  const existing = db.prepare("SELECT code FROM accounts WHERE code LIKE ?").all(group.prefix + "%").map(r => r.code);
  let n = 1;
  let code;
  do { code = group.prefix + String(n).padStart(4 - group.prefix.length, "0"); n++; } while (existing.includes(code));
  return code;
}
app.get("/api/account-groups/:id/next-code", (req, res) => {
  const code = nextCodeForGroup(req.params.id);
  if (!code) return res.status(404).json({ error: "Group not found" });
  res.json({ code });
});

app.post("/api/accounts", (req, res) => {
  const { name, type, group_id, linked_party_id, linked_charge_code } = req.body;
  let { code } = req.body;
  if (!name) return res.status(400).json({ error: "Account name is required" });
  let finalType = type;
  if (group_id) {
    const group = db.prepare("SELECT * FROM account_groups WHERE id=?").get(group_id);
    if (!group) return res.status(400).json({ error: "Selected group not found" });
    finalType = group.type;
    if (!code) code = nextCodeForGroup(group_id);
  }
  if (!code || !finalType) return res.status(400).json({ error: "Code and type are required (or pick a Group to auto-number)" });
  if (db.prepare("SELECT code FROM accounts WHERE code=?").get(code)) {
    return res.status(400).json({ error: `Account code "${code}" already exists` });
  }
  if (linked_party_id && !db.prepare("SELECT id FROM parties WHERE id=?").get(linked_party_id)) {
    return res.status(400).json({ error: "Linked client not found" });
  }
  db.prepare(`INSERT INTO accounts (code, name, type, group_id, linked_party_id, linked_charge_code) VALUES (?,?,?,?,?,?)`)
    .run(code, name, finalType, group_id || null, linked_party_id || null, linked_charge_code || null);
  // If this account is linked to a charge code, point that charge code's postings at the new account.
  if (linked_charge_code) {
    db.prepare("UPDATE charge_codes SET account_code=? WHERE code=?").run(code, linked_charge_code);
  }
  res.json(db.prepare("SELECT * FROM accounts WHERE code=?").get(code));
});
// Edit an account — name, group, and which party it's linked to (e.g. re-pointing a client's
// Receivable sub-account, or a vendor's Payable sub-account, to a different party). The account's
// code and type stay fixed once created (changing type would orphan its existing ledger postings).
app.put("/api/accounts/:code", (req, res) => {
  const cur = db.prepare("SELECT * FROM accounts WHERE code=?").get(req.params.code);
  if (!cur) return res.status(404).json({ error: "Account not found" });
  const { name, group_id, linked_party_id, linked_charge_code } = req.body;
  if (linked_party_id && !db.prepare("SELECT id FROM parties WHERE id=?").get(linked_party_id)) {
    return res.status(400).json({ error: "Linked party not found" });
  }
  db.prepare(`UPDATE accounts SET name=?, group_id=?, linked_party_id=?, linked_charge_code=? WHERE code=?`)
    .run(name ?? cur.name, group_id !== undefined ? (group_id || null) : cur.group_id,
         linked_party_id !== undefined ? (linked_party_id || null) : cur.linked_party_id,
         linked_charge_code !== undefined ? (linked_charge_code || null) : cur.linked_charge_code, cur.code);
  if (linked_charge_code) {
    db.prepare("UPDATE charge_codes SET account_code=? WHERE code=?").run(cur.code, linked_charge_code);
  }
  logActivity(req, "account_updated", `Account ${cur.code} updated`);
  res.json(db.prepare("SELECT * FROM accounts WHERE code=?").get(cur.code));
});
// Delete an account — only allowed while its ledger balance is exactly zero (no net debit/credit
// ever posted, or fully offset), so deleting an account can never silently drop real transactions.
app.delete("/api/accounts/:code", requireDelete, (req, res) => {
  const cur = db.prepare("SELECT * FROM accounts WHERE code=?").get(req.params.code);
  if (!cur) return res.status(404).json({ error: "Account not found" });
  const bal = accountBalance(cur.code);
  if (bal.dr !== 0 || bal.cr !== 0) {
    return res.status(400).json({ error: `This account has transactions posted to it (Debit ${bal.dr}, Credit ${bal.cr}) — it can only be deleted once its balance is zero.` });
  }
  const reason = (req.body && req.body.reason || "").trim();
  if (!reason) return res.status(400).json({ error: "A reason is required to delete an account" });
  db.prepare("DELETE FROM accounts WHERE code=?").run(cur.code);
  logActivity(req, "account_deleted", `Account ${cur.code} (${cur.name}) deleted — reason: ${reason}`);
  res.json({ ok: true });
});

// Auto-link a party to its own Receivable (client) or Payable (vendor) sub-account — created once,
// under whichever account group is tagged for that role, and left alone after that so the person
// can still repoint or rename it manually from Chart of Accounts without it being recreated.
function ensurePartyAccount(partyId, role) {
  const groupNamePrefix = role === "vendor" ? "Accounts Payable" : "Accounts Receivable";
  const existing = db.prepare("SELECT code FROM accounts WHERE linked_party_id=? AND type=?").get(partyId, role === "vendor" ? "Liability" : "Asset");
  if (existing) return existing.code;
  const group = db.prepare("SELECT * FROM account_groups WHERE name=?").get(groupNamePrefix)
    || db.prepare("SELECT * FROM account_groups WHERE type=? ORDER BY id LIMIT 1").get(role === "vendor" ? "Liability" : "Asset");
  if (!group) return null;
  const party = db.prepare("SELECT * FROM parties WHERE id=?").get(partyId);
  if (!party) return null;
  const code = nextCodeForGroup(group.id);
  if (!code) return null;
  db.prepare(`INSERT INTO accounts (code, name, type, group_id, linked_party_id) VALUES (?,?,?,?,?)`)
    .run(code, party.name, group.type, group.id, partyId);
  return code;
}

app.get("/api/vouchers", (req, res) => {
  const vouchers = db.prepare("SELECT * FROM vouchers ORDER BY id DESC").all();
  const lines = db.prepare("SELECT * FROM voucher_lines WHERE voucher_id=?");
  res.json(vouchers.map(v => ({ ...v, lines: lines.all(v.id) })));
});
app.get("/api/vouchers/:id", (req, res) => {
  const v = db.prepare("SELECT * FROM vouchers WHERE id=?").get(req.params.id);
  if (!v) return res.status(404).json({ error: "Voucher not found" });
  v.lines = db.prepare("SELECT * FROM voucher_lines WHERE voucher_id=?").all(v.id);
  res.json(v);
});
app.put("/api/vouchers/:id", (req, res) => {
  const v = db.prepare("SELECT * FROM vouchers WHERE id=?").get(req.params.id);
  if (!v) return res.status(404).json({ error: "Voucher not found" });
  if (v.source !== "manual") return res.status(400).json({ error: "Only manually-created vouchers can be edited — system-posted vouchers (invoices, receipts, bills, payments) are edited from their own screen." });
  const { date, narration, lines } = req.body;
  const drTotal = lines.reduce((s, l) => s + Number(l.debit || 0), 0);
  const crTotal = lines.reduce((s, l) => s + Number(l.credit || 0), 0);
  if (Math.abs(drTotal - crTotal) > 0.01 || drTotal <= 0) {
    return res.status(400).json({ error: "Voucher is not balanced" });
  }
  const tx = db.transaction(() => {
    db.prepare("UPDATE vouchers SET date=?, narration=? WHERE id=?").run(date, narration, v.id);
    db.prepare("DELETE FROM voucher_lines WHERE voucher_id=?").run(v.id);
    const insLine = db.prepare("INSERT INTO voucher_lines (voucher_id, account_code, debit, credit) VALUES (?,?,?,?)");
    lines.forEach(l => insLine.run(v.id, l.account, l.debit || 0, l.credit || 0));
  });
  tx();
  logActivity(req, "voucher_edited", `Edited voucher ${v.no}`);
  res.json({ id: v.id, no: v.no });
});
app.get("/api/voucher-types", (req, res) => {
  res.json([
    { code: "CPV", label: "Cash Payment Voucher" },
    { code: "CRV", label: "Cash Receipt Voucher" },
    { code: "BPV", label: "Bank Payment Voucher" },
    { code: "BRV", label: "Bank Receipt Voucher" },
    { code: "JV", label: "Journal Voucher" },
  ]);
});
app.post("/api/vouchers", (req, res) => {
  const { date, narration, lines } = req.body;
  const voucherType = MANUAL_VOUCHER_TYPES.includes(req.body.voucher_type) ? req.body.voucher_type : "JV";
  const drTotal = lines.reduce((s, l) => s + Number(l.debit || 0), 0);
  const crTotal = lines.reduce((s, l) => s + Number(l.credit || 0), 0);
  if (Math.abs(drTotal - crTotal) > 0.01 || drTotal <= 0) {
    return res.status(400).json({ error: "Voucher is not balanced" });
  }
  const v = postVoucher({ date, narration, source: "manual", lines, voucherType });
  logActivity(req, "voucher_posted", `${voucherType} ${v.no} — ${narration}`);
  res.json(v);
});

app.get("/api/ledger/:code", (req, res) => {
  const rows = db.prepare(`
    SELECT vl.id, vl.debit, vl.credit, vl.reconciled, vl.reconciled_date, v.date, v.no, v.narration
    FROM voucher_lines vl JOIN vouchers v ON v.id = vl.voucher_id
    WHERE vl.account_code = ? ORDER BY v.date, v.id`).all(req.params.code);
  let running = 0;
  const withBalance = rows.map(r => { running += r.debit - r.credit; return { ...r, balance: running }; });
  res.json(withBalance);
});

/* ---- Bank Reconciliation ---- */
// Any Asset-type account can be reconciled against a statement (typically the cash/bank accounts).
app.get("/api/bank-accounts", (req, res) => {
  res.json(db.prepare("SELECT code, name FROM accounts WHERE type='Asset' AND code != '1000' ORDER BY code").all());
});
app.post("/api/ledger-lines/:id/reconcile", (req, res) => {
  const reconciled = req.body.reconciled ? 1 : 0;
  const date = reconciled ? (req.body.date || new Date().toISOString().slice(0, 10)) : null;
  db.prepare("UPDATE voucher_lines SET reconciled=?, reconciled_date=? WHERE id=?").run(reconciled, date, req.params.id);
  res.json({ ok: true });
});

/* ---- Receivables ---- */
app.get("/api/receivables", (req, res) => {
  const rows = db.prepare(`
    SELECT i.*, j.job_no, j.client FROM invoices i JOIN jobs j ON j.id = i.job_id ORDER BY i.id DESC`).all();
  res.json(rows);
});
app.post("/api/receivables/:invoiceId/receipt", (req, res) => {
  const inv = db.prepare("SELECT * FROM invoices WHERE id=?").get(req.params.invoiceId);
  if (!inv) return res.status(404).json({ error: "Invoice not found" });
  const { amount, bank_account, date, narration, payment_mode, reference_no } = req.body;
  const outstanding = inv.amount - inv.settled_amount;
  if (amount <= 0 || amount > outstanding + 0.01) return res.status(400).json({ error: "Invalid amount" });
  if (payment_mode === "Online" && !reference_no) return res.status(400).json({ error: "Enter the transaction number for an Online receipt" });
  if (payment_mode === "Cheque" && !reference_no) return res.status(400).json({ error: "Enter the cheque number for a Cheque receipt" });
  const modeNote = payment_mode === "Online" ? ` — Txn# ${reference_no}` : payment_mode === "Cheque" ? ` — Cheque# ${reference_no}` : "";
  postVoucher({
    date, narration: (narration ? `${narration} ` : "") + `Receipt against ${inv.txn}${modeNote}`, source: "receipt",
    paymentMode: payment_mode, referenceNo: reference_no,
    lines: [{ account: bank_account, debit: amount, credit: 0 }, { account: "1000", debit: 0, credit: amount }]
  });
  const newSettled = inv.settled_amount + amount;
  db.prepare("UPDATE invoices SET settled_amount=?, settled=? WHERE id=?")
    .run(newSettled, newSettled >= inv.amount - 0.01 ? 1 : 0, inv.id);
  logActivity(req, "receipt_posted", `Receipt of ${amount} against invoice ${inv.txn}`);
  res.json(db.prepare("SELECT * FROM invoices WHERE id=?").get(inv.id));
});

/* ---- Payables ---- */
// Preview only — doesn't consume the sequence, so cancelling the form doesn't burn a number.
app.get("/api/payables/next-no", (req, res) => {
  const yy = currentFY();
  const key = `BILL-${yy}`;
  const row = db.prepare("SELECT last_no FROM job_sequences WHERE year=?").get(key);
  const next = (row ? row.last_no : 0) + 1;
  res.json({ preview: `BILL-${String(next).padStart(5, "0")}/${yy}` });
});
/* ---------------------------------------------------------------- */
/* JOB COSTS — draft cost/payable line items (mirrors job_charges).   */
/* "Generate Bill" bundles a vendor's draft lines into one actual     */
/* ap_bills row + GL posting, same as "Generate Invoice" does for     */
/* revenue charge lines.                                              */
/* ---------------------------------------------------------------- */
function costLinesForJob(jobId) {
  const sizes = equipmentSizesForJob(jobId);
  const rows = db.prepare("SELECT * FROM job_costs WHERE job_id=? ORDER BY id").all(jobId);
  return rows.map(c => {
    const qty = c.qty !== null && c.qty !== undefined ? c.qty : (c.size ? (sizes[c.size] || 0) : 0);
    const amt = (c.qty !== null && c.rate !== null) ? Math.round(qty * c.rate * 100) / 100 : c.amount;
    const rate = c.exchange_rate || 1;
    return { ...c, qty, amt, base_amt: Math.round(amt * rate * 100) / 100 };
  });
}
app.get("/api/jobs/:id/costs", (req, res) => {
  res.json(costLinesForJob(req.params.id));
});
app.post("/api/jobs/:id/costs", (req, res) => {
  const job = db.prepare("SELECT * FROM jobs WHERE id=?").get(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found" });
  if (!job.booking_saved) return res.status(400).json({ error: "Save Booking Info first — cost/payable lines can't be added until the booking has been saved." });
  const { vendor, description, size, expense_account, charge_id, charge_ref } = req.body;
  const currency = req.body.currency || "AED";
  const exchange_rate = currency === "AED" ? 1 : Number(req.body.exchange_rate) || 1;
  const billType = req.body.bill_type === "Advance" ? "Advance" : "Regular";
  if (!vendor) return res.status(400).json({ error: "Vendor is required" });
  if (currency !== "AED" && !req.body.exchange_rate) return res.status(400).json({ error: `Enter the exchange rate for ${currency} → AED` });
  ensurePartyRole(vendor, "is_vendor");
  const qty = req.body.qty !== undefined && req.body.qty !== "" ? Number(req.body.qty) : null;
  const rate = req.body.rate !== undefined && req.body.rate !== "" ? Number(req.body.rate) : null;
  const amount = (qty !== null && rate !== null) ? null : Number(req.body.amount || 0);
  if (qty === null && rate === null && !amount) return res.status(400).json({ error: "Enter either Qty & Rate, or a flat Amount" });
  const info = db.prepare(`INSERT INTO job_costs (job_id, vendor, description, size, qty, rate, amount, currency, exchange_rate, expense_account, bill_type, charge_id, charge_ref)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(req.params.id, vendor, description || "", size || null, qty, rate, amount || 0, currency, exchange_rate, expense_account || "5020", billType, charge_id || null, charge_ref || null);
  logActivity(req, "job_cost_added", `Draft cost added — job ${req.params.id}, vendor ${vendor}`);
  res.json({ id: info.lastInsertRowid });
});
app.put("/api/costs/:rowId", (req, res) => {
  const cur = db.prepare("SELECT * FROM job_costs WHERE id=?").get(req.params.rowId);
  if (!cur) return res.status(404).json({ error: "Cost line not found" });
  if (cur.bill_id) return res.status(400).json({ error: "This cost line is already part of a generated bill and can no longer be edited." });
  const { vendor, description, size, expense_account, charge_id, charge_ref } = req.body;
  const currency = req.body.currency || cur.currency;
  const exchange_rate = currency === "AED" ? 1 : Number(req.body.exchange_rate) || cur.exchange_rate;
  const billType = req.body.bill_type === "Advance" ? "Advance" : "Regular";
  const qty = req.body.qty !== undefined && req.body.qty !== "" ? Number(req.body.qty) : null;
  const rate = req.body.rate !== undefined && req.body.rate !== "" ? Number(req.body.rate) : null;
  const amount = (qty !== null && rate !== null) ? 0 : Number(req.body.amount ?? cur.amount);
  db.prepare(`UPDATE job_costs SET vendor=?, description=?, size=?, qty=?, rate=?, amount=?, currency=?, exchange_rate=?, expense_account=?, bill_type=?, charge_id=?, charge_ref=? WHERE id=?`)
    .run(vendor ?? cur.vendor, description ?? cur.description, size ?? cur.size, qty, rate, amount, currency, exchange_rate, expense_account ?? cur.expense_account, billType,
         req.body.hasOwnProperty("charge_id") ? (charge_id || null) : cur.charge_id, req.body.hasOwnProperty("charge_ref") ? (charge_ref || null) : cur.charge_ref, cur.id);
  res.json({ ok: true });
});
app.delete("/api/costs/:rowId", (req, res) => {
  const cur = db.prepare("SELECT * FROM job_costs WHERE id=?").get(req.params.rowId);
  if (!cur) return res.status(404).json({ error: "Cost line not found" });
  if (cur.bill_id) return res.status(400).json({ error: "This cost line is already part of a generated bill and cannot be deleted — delete the bill instead if it's wrong." });
  db.prepare("DELETE FROM job_costs WHERE id=?").run(req.params.rowId);
  res.json({ ok: true });
});

// The Generate Bill step: bundles every still-draft cost line for one vendor on this job into a
// single real vendor bill (its own bill_no, posted to the ledger) — exactly like Generate Invoice
// does for a job's revenue charge lines.
app.post("/api/jobs/:id/generate-bill", (req, res) => {
  const jobId = req.params.id;
  const { vendor } = req.body;
  if (!vendor) return res.status(400).json({ error: "Pick which vendor's draft cost lines to bill" });
  const job = db.prepare("SELECT * FROM jobs WHERE id=?").get(jobId);
  if (!job) return res.status(404).json({ error: "Job not found" });
  if (!job.charges_approved) return res.status(400).json({ error: "Charges must be approved on this job before a vendor bill can be generated." });

  const draftRows = db.prepare("SELECT * FROM job_costs WHERE job_id=? AND vendor=? COLLATE NOCASE AND bill_id IS NULL").all(jobId, vendor);
  if (!draftRows.length) return res.status(400).json({ error: `No draft cost lines for "${vendor}" on this job` });

  const lines = costLinesForJob(jobId).filter(l => draftRows.some(d => d.id === l.id));
  const isAdvance = lines.every(l => l.bill_type === "Advance");
  const totalFace = lines.reduce((s, l) => s + l.amt, 0);
  const totalBase = lines.reduce((s, l) => s + l.base_amt, 0);
  if (totalFace <= 0) return res.status(400).json({ error: "These draft cost lines total zero — nothing to bill" });

  // All lines must share one currency to become one bill (matches how a single vendor bill works elsewhere).
  const currencies = new Set(lines.map(l => l.currency));
  if (currencies.size > 1) return res.status(400).json({ error: "Draft cost lines for this vendor use different currencies — generate them as separate bills, one currency at a time." });
  const currency = lines[0].currency;
  const exchangeRate = lines[0].exchange_rate || 1;

  const billNo = billNoSeed();
  const chargeRefCombined = [...new Set(lines.map(l => l.charge_ref).filter(Boolean))].join("; ") || null;
  const info = db.prepare(`INSERT INTO ap_bills (bill_no, vendor, job_id, date, amount, currency, exchange_rate, base_amount, against_type, against_ref, bill_type, charge_ref)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(billNo, vendor, jobId, new Date().toISOString().slice(0, 10), totalFace, currency, exchangeRate, totalBase,
         isAdvance ? "Advance" : "Service", lines.map(l => l.description).filter(Boolean).join("; ") || "Job cost", isAdvance ? "Advance" : "Regular", chargeRefCombined);
  const billId = info.lastInsertRowid;
  db.prepare("INSERT OR IGNORE INTO ap_bill_jobs (bill_id, job_id) VALUES (?,?)").run(billId, jobId);

  const updateLine = db.prepare("UPDATE job_costs SET bill_id=? WHERE id=?");
  lines.forEach(l => updateLine.run(billId, l.id));

  // Post per distinct expense account so the ledger stays accurate even if lines used different accounts.
  const equityOrAdvanceAcct = isAdvance ? advancesToVendorsAccount() : null;
  const byAccount = {};
  lines.forEach(l => {
    const acct = isAdvance ? equityOrAdvanceAcct : (l.expense_account || "5020");
    byAccount[acct] = (byAccount[acct] || 0) + l.base_amt;
  });
  const jvLines = Object.entries(byAccount).map(([acct, amt]) => ({ account: acct, debit: amt, credit: 0 }));
  jvLines.push({ account: "2000", debit: 0, credit: totalBase });
  postVoucher({
    date: new Date().toISOString().slice(0, 10),
    narration: `${isAdvance ? "Advance " : ""}Vendor bill ${billNo} — ${vendor} — generated from ${lines.length} cost line(s) on job ${job.job_no}`,
    source: "bill", lines: jvLines
  });
  logActivity(req, "vendor_bill_generated", `Bill ${billNo} generated for ${vendor} from ${lines.length} draft cost line(s) — job ${job.job_no}`);
  res.json(db.prepare("SELECT * FROM ap_bills WHERE id=?").get(billId));
});

app.get("/api/jobs/:id/payables", (req, res) => {
  const jobId = req.params.id;
  const rows = db.prepare(`
    SELECT b.* FROM ap_bills b WHERE b.job_id = ?
    UNION
    SELECT b.* FROM ap_bills b JOIN ap_bill_jobs j ON j.bill_id=b.id WHERE j.job_id = ?
    ORDER BY id DESC`).all(jobId, jobId);
  res.json(rows);
});
app.get("/api/payables", (req, res) => {
  const bills = db.prepare("SELECT * FROM ap_bills ORDER BY id DESC").all();
  const jobsStmt = db.prepare(`SELECT j.id, j.job_no FROM ap_bill_jobs abj JOIN jobs j ON j.id=abj.job_id WHERE abj.bill_id=?`);
  res.json(bills.map(b => ({ ...b, jobs: jobsStmt.all(b.id) })));
});
app.post("/api/payables", (req, res) => {
  const { vendor, bill_no, job_id, job_ids, vessel_id, voyage_id, date, expense_account, against_type, against_ref, size } = req.body;
  const currency = req.body.currency || "AED";
  const exchangeRate = currency === "AED" ? 1 : (Number(req.body.exchange_rate) || 0);
  const billType = req.body.bill_type === "Advance" ? "Advance" : "Regular";
  // Same pattern as Charges: if qty & rate are both given, the amount is computed (qty × rate);
  // otherwise the caller's flat amount is used as-is.
  const qty = req.body.qty !== undefined && req.body.qty !== "" ? Number(req.body.qty) : null;
  const rate = req.body.rate !== undefined && req.body.rate !== "" ? Number(req.body.rate) : null;
  const amount = (qty !== null && rate !== null) ? Math.round(qty * rate * 100) / 100 : Number(req.body.amount);
  if (!vendor || !amount) return res.status(400).json({ error: "Vendor and amount required" });
  if (currency !== "AED" && exchangeRate <= 0) return res.status(400).json({ error: `Enter the exchange rate for ${currency} → AED` });
  ensurePartyRole(vendor, "is_vendor");
  const finalBillNo = bill_no || billNoSeed();
  const baseAmount = Math.round(amount * exchangeRate * 100) / 100;
  const postingAccount = billType === "Advance" ? advancesToVendorsAccount() : (expense_account || "5020");
  const info = db.prepare(`INSERT INTO ap_bills (bill_no, vendor, job_id, vessel_id, voyage_id, date, amount, currency, exchange_rate, base_amount, against_type, against_ref, size, qty, rate, bill_type)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(finalBillNo, vendor, job_id || null, vessel_id || null, voyage_id || null, date, amount, currency, exchangeRate, baseAmount,
         billType === "Advance" ? "Advance" : (against_type || "Service"), against_ref || (billType === "Advance" ? "Advance payment" : ""), size || null, qty, rate, billType);
  const billId = info.lastInsertRowid;
  const allJobIds = Array.from(new Set([...(job_id ? [job_id] : []), ...(Array.isArray(job_ids) ? job_ids : [])]));
  if (allJobIds.length) {
    const insJob = db.prepare("INSERT OR IGNORE INTO ap_bill_jobs (bill_id, job_id) VALUES (?,?)");
    allJobIds.forEach(jid => insJob.run(billId, jid));
  }
  const narrationSuffix = against_type === "Charge" ? ` (against charge: ${against_ref})` : (against_ref ? ` (${against_ref})` : "");
  const fxNote = currency !== "AED" ? ` [${currency} ${amount} @ ${exchangeRate}]` : "";
  postVoucher({
    date, narration: `${billType === "Advance" ? "Advance " : ""}Vendor bill ${finalBillNo} — ${vendor}${narrationSuffix}${fxNote}`, source: "bill",
    lines: [{ account: postingAccount, debit: baseAmount, credit: 0 }, { account: "2000", debit: 0, credit: baseAmount }]
  });
  logActivity(req, "vendor_bill_created", `${billType === "Advance" ? "Advance bill" : "Bill"} ${finalBillNo} — ${vendor} — ${currency} ${amount} (${allJobIds.length} job(s) linked)`);
  res.json(db.prepare("SELECT * FROM ap_bills WHERE id=?").get(billId));
});
// Bills can be edited (vendor, narration, expense account, dates/job links) but NOT the currency or
// exchange rate once posted — those are fixed at the accounting-period exchange rate on the day the
// bill was raised. To correct a wrong rate, delete this bill and re-enter it.
// Bills can be edited (vendor, bill#, date, amount, against, cost account, bill type) as long as no
// payment has been recorded yet — but NOT the currency or exchange rate, which are fixed at the rate
// on the day the bill was raised. If the amount changes, a small adjustment voucher corrects the GL
// rather than silently editing the original posting, so the ledger stays auditable.
app.put("/api/payables/:id", (req, res) => {
  const bill = db.prepare("SELECT * FROM ap_bills WHERE id=?").get(req.params.id);
  if (!bill) return res.status(404).json({ error: "Bill not found" });
  if (bill.settled_amount > 0) return res.status(400).json({ error: "This bill already has payments recorded against it and can no longer be edited — reverse the payment first if a correction is needed." });
  if (req.body.currency !== undefined && req.body.currency !== bill.currency) {
    return res.status(400).json({ error: "Currency cannot be changed once a bill is posted. Delete this bill and re-enter it with the correct currency." });
  }
  if (req.body.exchange_rate !== undefined && Number(req.body.exchange_rate) !== bill.exchange_rate) {
    return res.status(400).json({ error: "Exchange rate cannot be changed once a bill is posted. Delete this bill and re-enter it with the correct rate." });
  }
  const { vendor, bill_no, date, against_type, against_ref, expense_account } = req.body;
  const billType = req.body.bill_type === "Advance" ? "Advance" : bill.bill_type;
  const newAmount = req.body.amount !== undefined ? Number(req.body.amount) : bill.amount;
  const newBaseAmount = Math.round(newAmount * bill.exchange_rate * 100) / 100;

  db.prepare(`UPDATE ap_bills SET vendor=?, bill_no=?, date=?, against_type=?, against_ref=?, amount=?, base_amount=?, bill_type=? WHERE id=?`)
    .run(vendor ?? bill.vendor, bill_no ?? bill.bill_no, date ?? bill.date, against_type ?? bill.against_type, against_ref ?? bill.against_ref,
         newAmount, newBaseAmount, billType, bill.id);

  const delta = Math.round((newBaseAmount - bill.base_amount) * 100) / 100;
  if (Math.abs(delta) > 0.004) {
    const acct = billType === "Advance" ? advancesToVendorsAccount() : (expense_account || "5020");
    postVoucher({
      date: date || bill.date,
      narration: `Adjustment to bill ${bill.bill_no} — ${vendor ?? bill.vendor} (amount corrected)`,
      source: "bill",
      lines: delta > 0
        ? [{ account: acct, debit: delta, credit: 0 }, { account: "2000", debit: 0, credit: delta }]
        : [{ account: "2000", debit: -delta, credit: 0 }, { account: acct, debit: 0, credit: -delta }]
    });
  }
  logActivity(req, "vendor_bill_edited", `Bill ${bill.bill_no} edited${Math.abs(delta) > 0.004 ? ` — amount adjusted by ${delta}` : ""}`);
  res.json(db.prepare("SELECT * FROM ap_bills WHERE id=?").get(bill.id));
});
app.delete("/api/payables/:id", requireDelete, (req, res) => {
  const bill = db.prepare("SELECT * FROM ap_bills WHERE id=?").get(req.params.id);
  if (!bill) return res.status(404).json({ error: "Bill not found" });
  if (bill.settled_amount > 0) return res.status(400).json({ error: "This bill already has payments recorded against it and cannot be deleted." });
  const reason = (req.body && req.body.reason || "").trim();
  if (!reason) return res.status(400).json({ error: "A reason/comment is required to delete a bill." });
  // Reverse the original posting with an equal-and-opposite entry rather than silently deleting it.
  const acct = bill.bill_type === "Advance" ? advancesToVendorsAccount() : "5020";
  postVoucher({
    date: new Date().toISOString().slice(0, 10),
    narration: `Reversal of bill ${bill.bill_no} — ${bill.vendor} — cancelled: ${reason}`,
    source: "bill",
    lines: [{ account: "2000", debit: bill.base_amount, credit: 0 }, { account: acct, debit: 0, credit: bill.base_amount }]
  });
  db.prepare("DELETE FROM ap_bill_jobs WHERE bill_id=?").run(bill.id);
  db.prepare("UPDATE job_costs SET bill_id=NULL WHERE bill_id=?").run(bill.id);
  db.prepare("DELETE FROM ap_bills WHERE id=?").run(bill.id);
  logActivity(req, "vendor_bill_deleted", `Bill ${bill.bill_no} deleted — reason: ${reason}`);
  res.json({ ok: true });
});
app.post("/api/payables/:billId/payment", (req, res) => {
  const bill = db.prepare("SELECT * FROM ap_bills WHERE id=?").get(req.params.billId);
  if (!bill) return res.status(404).json({ error: "Bill not found" });
  const { amount, bank_account, date, narration, payment_mode, reference_no } = req.body;
  const outstanding = bill.amount - bill.settled_amount;
  if (amount <= 0 || amount > outstanding + 0.01) return res.status(400).json({ error: "Invalid amount" });
  if (payment_mode === "Online" && !reference_no) return res.status(400).json({ error: "Enter the transaction number for an Online payment" });
  if (payment_mode === "Cheque" && !reference_no) return res.status(400).json({ error: "Enter the cheque number for a Cheque payment" });
  const modeNote = payment_mode === "Online" ? ` — Txn# ${reference_no}` : payment_mode === "Cheque" ? ` — Cheque# ${reference_no}` : "";
  postVoucher({
    date, narration: (narration ? `${narration} ` : "") + `Payment against ${bill.bill_no} — ${bill.vendor}${modeNote}`, source: "payment",
    paymentMode: payment_mode, referenceNo: reference_no,
    lines: [{ account: "2000", debit: amount, credit: 0 }, { account: bank_account, debit: 0, credit: amount }]
  });
  const newSettled = bill.settled_amount + amount;
  db.prepare("UPDATE ap_bills SET settled_amount=?, settled=? WHERE id=?")
    .run(newSettled, newSettled >= bill.amount - 0.01 ? 1 : 0, bill.id);
  logActivity(req, "payment_posted", `Payment of ${amount} against bill ${bill.bill_no} — ${bill.vendor}`);
  res.json(db.prepare("SELECT * FROM ap_bills WHERE id=?").get(bill.id));
});

/* ---------------------------------------------------------------- */
/* PROFIT & LOSS — by Client / Vessel / Voyage, from job revenue+cost  */
/* ---------------------------------------------------------------- */
// Revenue comes from posted invoices (converted to AED via each invoice's own exchange rate);
// Cost comes from vendor bills linked to the job (already stored in AED as base_amount).
app.get("/api/reports/pl", (req, res) => {
  const { client, vessel_id, voyage_id, from, to } = req.query;
  let jobs = db.prepare("SELECT * FROM jobs").all();
  if (client) jobs = jobs.filter(j => j.client === client);
  if (vessel_id) jobs = jobs.filter(j => String(j.vessel_id) === String(vessel_id));
  if (voyage_id) jobs = jobs.filter(j => String(j.voyage_id) === String(voyage_id));
  if (from) jobs = jobs.filter(j => (j.job_date || "") >= from);
  if (to) jobs = jobs.filter(j => (j.job_date || "") <= to);

  const invStmt = db.prepare("SELECT COALESCE(SUM(amount * COALESCE(exchange_rate,1)),0) t FROM invoices WHERE job_id=?");
  const rows = jobs.map(j => {
    const revenue = invStmt.get(j.id).t;
    const cost = baseCostForJobIds([j.id]);
    return {
      job_id: j.id, job_no: j.job_no, client: j.client, vessel_id: j.vessel_id, voyage_id: j.voyage_id,
      job_date: j.job_date, revenue, cost, profit: revenue - cost,
      margin_pct: revenue > 0 ? Math.round(((revenue - cost) / revenue) * 1000) / 10 : 0,
    };
  }).filter(r => r.revenue || r.cost);
  const totals = rows.reduce((t, r) => ({ revenue: t.revenue + r.revenue, cost: t.cost + r.cost, profit: t.profit + r.profit }), { revenue: 0, cost: 0, profit: 0 });
  res.json({ rows, totals });
});

/* ---------------------------------------------------------------- */
/* BALANCE SHEET — as of a given month/year end date                  */
/* ---------------------------------------------------------------- */
app.get("/api/reports/balance-sheet", (req, res) => {
  const asOf = req.query.asOf || new Date().toISOString().slice(0, 10);
  const fyStart = `20${currentFY()}-01-01`;
  const accounts = db.prepare("SELECT * FROM accounts ORDER BY code").all();
  const balAsOf = db.prepare(`
    SELECT COALESCE(SUM(vl.debit),0) dr, COALESCE(SUM(vl.credit),0) cr
    FROM voucher_lines vl JOIN vouchers v ON v.id=vl.voucher_id WHERE vl.account_code=? AND v.date <= ?`);
  const rows = accounts.map(a => {
    const b = balAsOf.get(a.code, asOf);
    return { code: a.code, name: a.name, type: a.type, balance: b.dr - b.cr };
  });
  const assets = rows.filter(r => r.type === "Asset" && Math.abs(r.balance) > 0.004);
  const liabilities = rows.filter(r => r.type === "Liability" && Math.abs(r.balance) > 0.004).map(r => ({ ...r, balance: -r.balance }));
  const equity = rows.filter(r => r.type === "Equity" && Math.abs(r.balance) > 0.004).map(r => ({ ...r, balance: -r.balance }));
  // Income/Expense accounts don't carry into the Balance Sheet directly — their year-to-date net
  // becomes "Current Year Earnings" under Equity, the same way a real close-out would net them.
  const incomeExpense = db.prepare(`
    SELECT a.type, COALESCE(SUM(vl.debit),0) dr, COALESCE(SUM(vl.credit),0) cr
    FROM voucher_lines vl JOIN vouchers v ON v.id=vl.voucher_id JOIN accounts a ON a.code=vl.account_code
    WHERE a.type IN ('Income','Expense') AND v.date BETWEEN ? AND ? GROUP BY a.type`).all(fyStart, asOf);
  let income = 0, expense = 0;
  incomeExpense.forEach(r => { if (r.type === "Income") income = r.cr - r.dr; else expense = r.dr - r.cr; });
  const currentYearEarnings = income - expense;
  const totalAssets = assets.reduce((s, r) => s + r.balance, 0);
  const totalLiabilities = liabilities.reduce((s, r) => s + r.balance, 0);
  const totalEquity = equity.reduce((s, r) => s + r.balance, 0) + currentYearEarnings;
  res.json({
    asOf, assets, liabilities, equity, currentYearEarnings,
    totalAssets, totalLiabilities, totalEquity,
    balanced: Math.abs(totalAssets - (totalLiabilities + totalEquity)) < 1,
  });
});

/* ---------------------------------------------------------------- */
/* CASH FLOW STATEMENT — movement through Cash & Bank accounts        */
/* ---------------------------------------------------------------- */
app.get("/api/reports/cash-flow", (req, res) => {
  const from = req.query.from || `20${currentFY()}-01-01`;
  const to = req.query.to || new Date().toISOString().slice(0, 10);
  const cashAccounts = db.prepare("SELECT code, name FROM accounts WHERE type='Asset' AND code != '1000'").all();
  const codes = cashAccounts.map(a => a.code);
  if (!codes.length) return res.json({ from, to, opening: 0, closing: 0, byCategory: [] });
  const ph = codes.map(()=>'?').join(',');

  const openingRow = db.prepare(`
    SELECT COALESCE(SUM(vl.debit),0) dr, COALESCE(SUM(vl.credit),0) cr
    FROM voucher_lines vl JOIN vouchers v ON v.id=vl.voucher_id WHERE vl.account_code IN (${ph}) AND v.date < ?`).get(...codes, from);
  const opening = openingRow.dr - openingRow.cr;

  const movement = db.prepare(`
    SELECT v.source, COALESCE(SUM(vl.debit),0) dr, COALESCE(SUM(vl.credit),0) cr
    FROM voucher_lines vl JOIN vouchers v ON v.id=vl.voucher_id
    WHERE vl.account_code IN (${ph}) AND v.date >= ? AND v.date <= ? GROUP BY v.source`).all(...codes, from, to);

  const label = { receipt: "Customer Receipts (Operating Inflow)", payment: "Vendor Payments (Operating Outflow)", opening: "Opening Balances", manual: "Other (Manual Vouchers)" };
  const byCategory = movement.map(m => ({ source: m.source, label: label[m.source] || m.source, net: m.dr - m.cr, inflow: m.dr, outflow: m.cr }));
  const netMovement = byCategory.reduce((s, r) => s + r.net, 0);
  res.json({ from, to, opening, closing: opening + netMovement, netMovement, byCategory, accounts: cashAccounts });
});

/* ---------------------------------------------------------------- */
/* CREDIT NOTES — reduce a client's receivable, optionally against a  */
/* specific invoice (or as a standalone adjustment with none picked)  */
/* ---------------------------------------------------------------- */
app.get("/api/credit-notes", (req, res) => {
  res.json(db.prepare(`
    SELECT cn.*, i.txn as invoice_txn FROM credit_notes cn LEFT JOIN invoices i ON i.id = cn.invoice_id
    ORDER BY cn.id DESC`).all());
});
app.post("/api/credit-notes", (req, res) => {
  const { client, invoice_id, date, reason, account_code } = req.body;
  const amount = Number(req.body.amount);
  if (!client || !amount) return res.status(400).json({ error: "Client and amount are required" });
  if (!account_code) return res.status(400).json({ error: "Pick which account this credit note reduces (e.g. a revenue or discount account)" });
  let invoice = null;
  if (invoice_id) {
    invoice = db.prepare("SELECT * FROM invoices WHERE id=?").get(invoice_id);
    if (!invoice) return res.status(400).json({ error: "Selected invoice not found" });
    const outstanding = invoice.amount - invoice.settled_amount;
    if (amount > outstanding + 0.01) return res.status(400).json({ error: `Credit note amount exceeds this invoice's outstanding balance (${outstanding.toFixed(2)})` });
  }
  const cnNo = nextSeq("CN", "CN", 4, true);
  const info = db.prepare(`INSERT INTO credit_notes (cn_no, client, invoice_id, date, amount, reason, account_code) VALUES (?,?,?,?,?,?,?)`)
    .run(cnNo, client, invoice_id || null, date, amount, reason || "", account_code);
  if (invoice) {
    const newSettled = invoice.settled_amount + amount;
    db.prepare("UPDATE invoices SET settled_amount=?, settled=? WHERE id=?")
      .run(newSettled, newSettled >= invoice.amount - 0.01 ? 1 : 0, invoice.id);
  }
  postVoucher({
    date, narration: `Credit note ${cnNo} — ${client}${invoice ? ` against ${invoice.txn}` : ""}${reason ? ` — ${reason}` : ""}`,
    source: "creditnote",
    lines: [{ account: account_code, debit: amount, credit: 0 }, { account: "1000", debit: 0, credit: amount }]
  });
  logActivity(req, "credit_note_created", `Credit note ${cnNo} — ${client} — ${amount}${invoice ? ` against ${invoice.txn}` : ""}`);
  res.json(db.prepare("SELECT * FROM credit_notes WHERE id=?").get(info.lastInsertRowid));
});
// Amount/account/client are fixed once posted (they drove a GL entry and possibly an invoice
// settlement) — only the reason and date can be corrected. To change the amount, delete and re-issue.
app.put("/api/credit-notes/:id", (req, res) => {
  const cn = db.prepare("SELECT * FROM credit_notes WHERE id=?").get(req.params.id);
  if (!cn) return res.status(404).json({ error: "Credit note not found" });
  const { reason, date } = req.body;
  db.prepare("UPDATE credit_notes SET reason=?, date=? WHERE id=?").run(reason ?? cn.reason, date ?? cn.date, cn.id);
  logActivity(req, "credit_note_edited", `Credit note ${cn.cn_no} edited`);
  res.json(db.prepare("SELECT * FROM credit_notes WHERE id=?").get(cn.id));
});
app.delete("/api/credit-notes/:id", requireDelete, (req, res) => {
  const cn = db.prepare("SELECT * FROM credit_notes WHERE id=?").get(req.params.id);
  if (!cn) return res.status(404).json({ error: "Credit note not found" });
  const reason = (req.body && req.body.reason || "").trim();
  if (!reason) return res.status(400).json({ error: "A reason/comment is required to delete a credit note." });
  if (cn.invoice_id) {
    const invoice = db.prepare("SELECT * FROM invoices WHERE id=?").get(cn.invoice_id);
    if (invoice) {
      const newSettled = Math.max(0, invoice.settled_amount - cn.amount);
      db.prepare("UPDATE invoices SET settled_amount=?, settled=? WHERE id=?")
        .run(newSettled, newSettled >= invoice.amount - 0.01 ? 1 : 0, invoice.id);
    }
  }
  // Reverse the original GL entry with an equal-and-opposite voucher rather than silently deleting it —
  // keeps the ledger auditable.
  postVoucher({
    date: new Date().toISOString().slice(0, 10),
    narration: `Reversal of credit note ${cn.cn_no} — ${cn.client} — cancelled: ${reason}`,
    source: "creditnote",
    lines: [{ account: "1000", debit: cn.amount, credit: 0 }, { account: cn.account_code, debit: 0, credit: cn.amount }]
  });
  db.prepare("DELETE FROM credit_notes WHERE id=?").run(cn.id);
  logActivity(req, "credit_note_deleted", `Credit note ${cn.cn_no} deleted — reason: ${reason}`);
  res.json({ ok: true });
});

/* ---------------------------------------------------------------- */
/* DEBIT NOTES — adjust a vendor's payable, optionally against a bill */
/* ---------------------------------------------------------------- */
app.get("/api/debit-notes", (req, res) => {
  res.json(db.prepare(`
    SELECT dn.*, b.bill_no FROM debit_notes dn LEFT JOIN ap_bills b ON b.id = dn.bill_id
    ORDER BY dn.id DESC`).all());
});
app.post("/api/debit-notes", (req, res) => {
  const { vendor, bill_id, date, reason, account_code } = req.body;
  const amount = Number(req.body.amount);
  if (!vendor || !amount) return res.status(400).json({ error: "Vendor and amount are required" });
  if (!account_code) return res.status(400).json({ error: "Pick which account this debit note reduces (e.g. a cost account)" });
  let bill = null;
  if (bill_id) {
    bill = db.prepare("SELECT * FROM ap_bills WHERE id=?").get(bill_id);
    if (!bill) return res.status(400).json({ error: "Selected bill not found" });
    const outstanding = bill.amount - bill.settled_amount;
    if (amount > outstanding + 0.01) return res.status(400).json({ error: `Debit note amount exceeds this bill's outstanding balance (${outstanding.toFixed(2)})` });
  }
  const dnNo = nextSeq("DN", "DN", 4, true);
  const info = db.prepare(`INSERT INTO debit_notes (dn_no, vendor, bill_id, date, amount, reason, account_code) VALUES (?,?,?,?,?,?,?)`)
    .run(dnNo, vendor, bill_id || null, date, amount, reason || "", account_code);
  if (bill) {
    const newSettled = bill.settled_amount + amount;
    db.prepare("UPDATE ap_bills SET settled_amount=?, settled=? WHERE id=?")
      .run(newSettled, newSettled >= bill.amount - 0.01 ? 1 : 0, bill.id);
  }
  postVoucher({
    date, narration: `Debit note ${dnNo} — ${vendor}${bill ? ` against ${bill.bill_no}` : ""}${reason ? ` — ${reason}` : ""}`,
    source: "debitnote",
    lines: [{ account: "2000", debit: amount, credit: 0 }, { account: account_code, debit: 0, credit: amount }]
  });
  logActivity(req, "debit_note_created", `Debit note ${dnNo} — ${vendor} — ${amount}${bill ? ` against ${bill.bill_no}` : ""}`);
  res.json(db.prepare("SELECT * FROM debit_notes WHERE id=?").get(info.lastInsertRowid));
});
app.put("/api/debit-notes/:id", (req, res) => {
  const dn = db.prepare("SELECT * FROM debit_notes WHERE id=?").get(req.params.id);
  if (!dn) return res.status(404).json({ error: "Debit note not found" });
  const { reason, date } = req.body;
  db.prepare("UPDATE debit_notes SET reason=?, date=? WHERE id=?").run(reason ?? dn.reason, date ?? dn.date, dn.id);
  logActivity(req, "debit_note_edited", `Debit note ${dn.dn_no} edited`);
  res.json(db.prepare("SELECT * FROM debit_notes WHERE id=?").get(dn.id));
});
app.delete("/api/debit-notes/:id", requireDelete, (req, res) => {
  const dn = db.prepare("SELECT * FROM debit_notes WHERE id=?").get(req.params.id);
  if (!dn) return res.status(404).json({ error: "Debit note not found" });
  const reason = (req.body && req.body.reason || "").trim();
  if (!reason) return res.status(400).json({ error: "A reason/comment is required to delete a debit note." });
  if (dn.bill_id) {
    const bill = db.prepare("SELECT * FROM ap_bills WHERE id=?").get(dn.bill_id);
    if (bill) {
      const newSettled = Math.max(0, bill.settled_amount - dn.amount);
      db.prepare("UPDATE ap_bills SET settled_amount=?, settled=? WHERE id=?")
        .run(newSettled, newSettled >= bill.amount - 0.01 ? 1 : 0, bill.id);
    }
  }
  postVoucher({
    date: new Date().toISOString().slice(0, 10),
    narration: `Reversal of debit note ${dn.dn_no} — ${dn.vendor} — cancelled: ${reason}`,
    source: "debitnote",
    lines: [{ account: dn.account_code, debit: dn.amount, credit: 0 }, { account: "2000", debit: 0, credit: dn.amount }]
  });
  db.prepare("DELETE FROM debit_notes WHERE id=?").run(dn.id);
  logActivity(req, "debit_note_deleted", `Debit note ${dn.dn_no} deleted — reason: ${reason}`);
  res.json({ ok: true });
});

app.get("/api/trial-balance", (req, res) => {
  const accounts = db.prepare("SELECT * FROM accounts ORDER BY code").all();
  res.json(accounts.map(a => ({ ...a, balance: accountBalance(a.code) })));
});

// Proper "for the month" trial balance: Opening Dr/Cr (net balance before the period), Debit/Credit
// (gross movement during the period), Closing Dr/Cr (net balance after the period) — same shape as a
// standard accounting trial balance report.
app.get("/api/trial-balance/period", (req, res) => {
  const from = req.query.from || `20${currentFY()}-01-01`;
  const to = req.query.to || new Date().toISOString().slice(0, 10);
  const accounts = db.prepare("SELECT * FROM accounts ORDER BY code").all();
  const openingQ = db.prepare(`
    SELECT COALESCE(SUM(vl.debit),0) dr, COALESCE(SUM(vl.credit),0) cr
    FROM voucher_lines vl JOIN vouchers v ON v.id = vl.voucher_id
    WHERE vl.account_code = ? AND v.date < ?`);
  const periodQ = db.prepare(`
    SELECT COALESCE(SUM(vl.debit),0) dr, COALESCE(SUM(vl.credit),0) cr
    FROM voucher_lines vl JOIN vouchers v ON v.id = vl.voucher_id
    WHERE vl.account_code = ? AND v.date >= ? AND v.date <= ?`);
  const rows = accounts.map(a => {
    const opening = openingQ.get(a.code, from);
    const period = periodQ.get(a.code, from, to);
    const openingNet = opening.dr - opening.cr;
    const closingNet = openingNet + period.dr - period.cr;
    return {
      code: a.code, name: a.name, type: a.type,
      openingDebit: openingNet > 0 ? openingNet : 0, openingCredit: openingNet < 0 ? -openingNet : 0,
      debit: period.dr, credit: period.cr,
      closingDebit: closingNet > 0 ? closingNet : 0, closingCredit: closingNet < 0 ? -closingNet : 0,
    };
  }).filter(r => r.openingDebit || r.openingCredit || r.debit || r.credit || r.closingDebit || r.closingCredit);
  const totals = rows.reduce((t, r) => ({
    openingDebit: t.openingDebit + r.openingDebit, openingCredit: t.openingCredit + r.openingCredit,
    debit: t.debit + r.debit, credit: t.credit + r.credit,
    closingDebit: t.closingDebit + r.closingDebit, closingCredit: t.closingCredit + r.closingCredit,
  }), { openingDebit: 0, openingCredit: 0, debit: 0, credit: 0, closingDebit: 0, closingCredit: 0 });
  res.json({ from, to, rows, totals });
});

/* ---------------------------------------------------------------- */
/* ADMIN: vessels, voyages, parties, users                           */
/* ---------------------------------------------------------------- */
app.get("/api/vessels", (req, res) => {
  const vessels = db.prepare("SELECT * FROM vessels ORDER BY name").all();
  const voyagesStmt = db.prepare("SELECT * FROM voyages WHERE vessel_id=?");
  return res.json(vessels.map(v => {
    const vendor = v.vendor_party_id ? db.prepare("SELECT id, name FROM parties WHERE id=?").get(v.vendor_party_id) : null;
    return { ...v, vendor_name: vendor ? vendor.name : null, voyages: voyagesStmt.all(v.id) };
  }));
});
// Vessel serial code — auto-generated as V-0001, V-0002, ... so a vessel can be looked up either
// by its name (dropdown) or by typing this short code directly (e.g. in Booking Info).
function vesselCodeSeed() {
  const n = db.prepare("SELECT COUNT(*) c FROM vessels").get().c + 1;
  return `V-${String(n).padStart(4, "0")}`;
}
app.post("/api/vessels", (req, res) => {
  const name = (req.body.name || "").trim();
  const vendor_party_id = req.body.vendor_party_id || null;
  if (!name) return res.status(400).json({ error: "Vessel name is required" });
  if (db.prepare("SELECT id FROM vessels WHERE name = ? COLLATE NOCASE").get(name)) {
    return res.status(400).json({ error: `Vessel "${name}" already exists` });
  }
  const code = vesselCodeSeed();
  const info = db.prepare("INSERT INTO vessels (name, vendor_party_id, code) VALUES (?,?,?)").run(name, vendor_party_id, code);
  res.json({ id: info.lastInsertRowid, name, vendor_party_id, code, voyages: [] });
});
// Look a vessel up by its serial code (e.g. V-0007) — same pattern as Party/Port code lookups.
app.get("/api/vessels/by-code/:code", (req, res) => {
  const vessel = db.prepare("SELECT * FROM vessels WHERE code = ? COLLATE NOCASE").get(req.params.code.trim());
  if (!vessel) return res.status(404).json({ error: `No vessel found with code "${req.params.code}"` });
  res.json(vessel);
});
app.put("/api/vessels/:id", (req, res) => {
  const vendor_party_id = req.body.vendor_party_id || null;
  db.prepare("UPDATE vessels SET vendor_party_id=? WHERE id=?").run(vendor_party_id, req.params.id);
  res.json({ ok: true });
});
app.delete("/api/vessels/:id", requireDelete, (req, res) => {
  db.prepare("DELETE FROM vessels WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});
app.post("/api/vessels/:id/voyages", (req, res) => {
  const no = (req.body.no || "").trim();
  const rotation_no = (req.body.rotation_no || "").trim();
  const { etd, eta, cut_off } = req.body;
  if (!no) return res.status(400).json({ error: "Voyage number is required" });
  if (db.prepare("SELECT id FROM voyages WHERE vessel_id=? AND no = ? COLLATE NOCASE").get(req.params.id, no)) {
    return res.status(400).json({ error: `Voyage "${no}" already exists for this vessel` });
  }
  if (rotation_no && db.prepare("SELECT id FROM voyages WHERE rotation_no = ? COLLATE NOCASE").get(rotation_no)) {
    return res.status(400).json({ error: `Rotation number "${rotation_no}" is already used by another voyage — it must be unique.` });
  }
  const info = db.prepare("INSERT INTO voyages (vessel_id, no, etd, eta, cut_off, rotation_no) VALUES (?,?,?,?,?,?)")
    .run(req.params.id, no, etd, eta, cut_off || null, rotation_no || null);
  res.json(db.prepare("SELECT * FROM voyages WHERE id=?").get(info.lastInsertRowid));
});
app.put("/api/voyages/:id", (req, res) => {
  const v = db.prepare("SELECT * FROM voyages WHERE id=?").get(req.params.id);
  if (!v) return res.status(404).json({ error: "Voyage not found" });
  const rotation_no = req.body.rotation_no !== undefined ? req.body.rotation_no.trim() : v.rotation_no;
  if (rotation_no && db.prepare("SELECT id FROM voyages WHERE rotation_no = ? COLLATE NOCASE AND id != ?").get(rotation_no, v.id)) {
    return res.status(400).json({ error: `Rotation number "${rotation_no}" is already used by another voyage — it must be unique.` });
  }
  const { no, etd, eta, cut_off } = req.body;
  db.prepare("UPDATE voyages SET no=?, etd=?, eta=?, cut_off=?, rotation_no=? WHERE id=?")
    .run(no ?? v.no, etd ?? v.etd, eta ?? v.eta, cut_off ?? v.cut_off, rotation_no || null, v.id);
  res.json(db.prepare("SELECT * FROM voyages WHERE id=?").get(v.id));
});
app.delete("/api/voyages/:id", requireDelete, (req, res) => {
  db.prepare("DELETE FROM voyages WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});
app.post("/api/voyages/:id/close", (req, res) => {
  db.prepare("UPDATE voyages SET closed=1 WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});
app.post("/api/voyages/:id/reopen", (req, res) => {
  db.prepare("UPDATE voyages SET closed=0 WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

app.get("/api/vessels/:id/jobs", (req, res) => {
  const jobs = db.prepare("SELECT id, job_no, client, direction FROM jobs WHERE vessel_id=? ORDER BY id DESC").all(req.params.id);
  res.json(jobs);
});
app.get("/api/voyages/:id/jobs", (req, res) => {
  const jobs = db.prepare("SELECT id, job_no, client, direction FROM jobs WHERE voyage_id=? ORDER BY id DESC").all(req.params.id);
  res.json(jobs);
});

// Financial P&L for one voyage: revenue from jobs on it, cost from vendor bills tied to it (directly or via its jobs)
app.get("/api/voyages/:id/pl", (req, res) => {
  const voyageId = req.params.id;
  const voyage = db.prepare("SELECT * FROM voyages WHERE id=?").get(voyageId);
  if (!voyage) return res.status(404).json({ error: "Voyage not found" });
  const jobs = db.prepare("SELECT * FROM jobs WHERE voyage_id=?").all(voyageId);
  const jobIds = jobs.map(j => j.id);
  const revenue = jobIds.length
    ? db.prepare(`SELECT COALESCE(SUM(amount),0) t FROM invoices WHERE job_id IN (${jobIds.map(()=>'?').join(',')})`).get(...jobIds).t
    : 0;
  const costDirect = db.prepare("SELECT COALESCE(SUM(amount),0) t FROM ap_bills WHERE voyage_id=?").get(voyageId).t;
  const cost = costDirect + costForJobIds(jobIds);
  res.json({ voyage, jobCount: jobs.length, revenue, cost, profit: revenue - cost });
});

app.get("/api/reports/outstanding-by-vessel", (req, res) => {
  const vessels = db.prepare("SELECT * FROM vessels ORDER BY name").all();
  res.json(vessels.map(v => {
    const jobs = db.prepare("SELECT id FROM jobs WHERE vessel_id=?").all(v.id).map(j=>j.id);
    const voyageIds = db.prepare("SELECT id FROM voyages WHERE vessel_id=?").all(v.id).map(r=>r.id);
    let arOutstanding = 0, apOutstanding = 0;
    if (jobs.length) {
      const ph = jobs.map(()=>'?').join(',');
      arOutstanding = db.prepare(`SELECT COALESCE(SUM(amount-settled_amount),0) t FROM invoices WHERE job_id IN (${ph})`).get(...jobs).t;
      apOutstanding += outstandingCostForJobIds(jobs);
    }
    apOutstanding += db.prepare("SELECT COALESCE(SUM(amount-settled_amount),0) t FROM ap_bills WHERE vessel_id=?").get(v.id).t;
    if (voyageIds.length) {
      const ph2 = voyageIds.map(()=>'?').join(',');
      apOutstanding += db.prepare(`SELECT COALESCE(SUM(amount-settled_amount),0) t FROM ap_bills WHERE voyage_id IN (${ph2}) AND (vessel_id IS NULL OR vessel_id != ?)`).get(...voyageIds, v.id).t;
    }
    return { vessel: v.name, ar_outstanding: arOutstanding, ap_outstanding: apOutstanding };
  }));
});

/* ---------------------------------------------------------------- */
/* VESSEL SCHEDULE — marketing email campaigns off a vessel/voyage    */
/* ---------------------------------------------------------------- */
app.get("/api/vessel-campaigns", (req, res) => {
  res.json(db.prepare("SELECT * FROM vessel_campaigns ORDER BY id DESC").all().map(campaignWithMeta));
});

app.get("/api/vessel-campaigns/:id", (req, res) => {
  const c = db.prepare("SELECT * FROM vessel_campaigns WHERE id=?").get(req.params.id);
  if (!c) return res.status(404).json({ error: "Not found" });
  const logs = db.prepare("SELECT * FROM email_logs WHERE related_type='vessel_schedule' AND related_ref=? ORDER BY id DESC").all(String(c.id));
  const byUser = {};
  logs.forEach(l => {
    const key = l.sent_by_username || "system";
    byUser[key] = byUser[key] || { sent: 0, failed: 0 };
    byUser[key][l.status === "sent" ? "sent" : "failed"]++;
  });
  res.json({ ...campaignWithMeta(c), logs, by_user: byUser });
});

app.post("/api/vessel-campaigns", (req, res) => {
  const b = req.body;
  if (!b.vessel_id || !b.voyage_id) return res.status(400).json({ error: "Vessel and voyage are required" });
  if (!b.subject || !b.message) return res.status(400).json({ error: "Subject and message are required" });
  const toEmails = parseEmails(b.to_list);
  if (!toEmails.length) return res.status(400).json({ error: "Add at least one valid email address in the To list" });
  const vessel = db.prepare("SELECT * FROM vessels WHERE id=?").get(b.vessel_id);
  const voyage = db.prepare("SELECT * FROM voyages WHERE id=?").get(b.voyage_id);
  if (!vessel || !voyage) return res.status(400).json({ error: "Vessel/voyage not found" });
  if (voyage.closed) return res.status(400).json({ error: "This voyage is closed — reopen it under Vessels & Voyages first" });
  const polList = cleanPortEtaList(b.pol_list);
  const podList = cleanPortEtaList(b.pod_list);
  if (!polList.length) return res.status(400).json({ error: "Add at least one Port of Loading" });
  if (!podList.length) return res.status(400).json({ error: "Add at least one Port of Discharge" });
  const base_url = `${req.protocol}://${req.get("host")}`;
  const info = db.prepare(`INSERT INTO vessel_campaigns
    (vessel_id, voyage_id, vessel_name, voyage_no, pol, pod, pol_list, pod_list, etd, eta, subject, message, to_list, cc_list, bcc_list,
     recipient_count, schedule_start_date, send_times, base_url, created_by_username)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(b.vessel_id, b.voyage_id, vessel.name, voyage.no,
      polList.map(p => p.port).join(", "), podList.map(p => p.port).join(", "),
      JSON.stringify(polList), JSON.stringify(podList),
      voyage.etd || "", voyage.eta || "",
      b.subject, b.message, b.to_list || "", b.cc_list || "", b.bcc_list || "",
      toEmails.length, b.schedule_start_date || null, JSON.stringify(b.send_times || []), base_url, req.session.user.username);
  logActivity(req, "vessel_campaign_created", `Created vessel schedule email "${b.subject}" for ${vessel.name} ${voyage.no}`);
  res.json(campaignWithMeta(db.prepare("SELECT * FROM vessel_campaigns WHERE id=?").get(info.lastInsertRowid)));
});

app.put("/api/vessel-campaigns/:id", (req, res) => {
  const c = db.prepare("SELECT * FROM vessel_campaigns WHERE id=?").get(req.params.id);
  if (!c) return res.status(404).json({ error: "Not found" });
  const b = req.body;
  const toEmails = b.to_list !== undefined ? parseEmails(b.to_list) : null;
  if (toEmails !== null && !toEmails.length) return res.status(400).json({ error: "Add at least one valid email address in the To list" });
  const polList = b.pol_list !== undefined ? cleanPortEtaList(b.pol_list) : null;
  const podList = b.pod_list !== undefined ? cleanPortEtaList(b.pod_list) : null;
  if (polList !== null && !polList.length) return res.status(400).json({ error: "Add at least one Port of Loading" });
  if (podList !== null && !podList.length) return res.status(400).json({ error: "Add at least one Port of Discharge" });
  db.prepare(`UPDATE vessel_campaigns SET subject=?, message=?, to_list=?, cc_list=?, bcc_list=?, recipient_count=?,
    pol=?, pod=?, pol_list=?, pod_list=?, schedule_start_date=?, send_times=? WHERE id=?`)
    .run(
      b.subject ?? c.subject, b.message ?? c.message,
      b.to_list ?? c.to_list, b.cc_list ?? c.cc_list, b.bcc_list ?? c.bcc_list,
      toEmails ? toEmails.length : c.recipient_count,
      polList ? polList.map(p => p.port).join(", ") : c.pol,
      podList ? podList.map(p => p.port).join(", ") : c.pod,
      polList ? JSON.stringify(polList) : c.pol_list,
      podList ? JSON.stringify(podList) : c.pod_list,
      b.schedule_start_date ?? c.schedule_start_date,
      b.send_times ? JSON.stringify(b.send_times) : c.send_times,
      req.params.id
    );
  logActivity(req, "vessel_campaign_updated", `Updated vessel schedule email #${req.params.id}`);
  res.json(campaignWithMeta(db.prepare("SELECT * FROM vessel_campaigns WHERE id=?").get(req.params.id)));
});

app.delete("/api/vessel-campaigns/:id", requireDelete, (req, res) => {
  db.prepare("DELETE FROM vessel_campaigns WHERE id=?").run(req.params.id);
  logActivity(req, "vessel_campaign_deleted", `Deleted vessel schedule email #${req.params.id}`);
  res.json({ ok: true });
});

app.post("/api/vessel-campaigns/:id/start", (req, res) => {
  const c = db.prepare("SELECT * FROM vessel_campaigns WHERE id=?").get(req.params.id);
  if (!c) return res.status(404).json({ error: "Not found" });
  if (!c.schedule_start_date) return res.status(400).json({ error: "Set a start date first" });
  const times = JSON.parse(c.send_times || "[]");
  if (!times.length) return res.status(400).json({ error: "Add at least one send time first" });
  db.prepare("UPDATE vessel_campaigns SET is_running=1, started_by_user_id=?, started_by_username=?, started_at=datetime('now'), last_sent_date=NULL, last_sent_times='[]' WHERE id=?")
    .run(req.session.user.id, req.session.user.username, req.params.id);
  logActivity(req, "vessel_campaign_started", `Started email schedule #${req.params.id} (${c.subject})`);
  res.json(campaignWithMeta(db.prepare("SELECT * FROM vessel_campaigns WHERE id=?").get(req.params.id)));
});

app.post("/api/vessel-campaigns/:id/stop", (req, res) => {
  const c = db.prepare("SELECT * FROM vessel_campaigns WHERE id=?").get(req.params.id);
  if (!c) return res.status(404).json({ error: "Not found" });
  db.prepare("UPDATE vessel_campaigns SET is_running=0 WHERE id=?").run(req.params.id);
  logActivity(req, "vessel_campaign_stopped", `Stopped email schedule #${req.params.id} (${c.subject})`);
  res.json(campaignWithMeta(db.prepare("SELECT * FROM vessel_campaigns WHERE id=?").get(req.params.id)));
});

app.post("/api/vessel-campaigns/:id/send-now", async (req, res) => {
  const c = db.prepare("SELECT * FROM vessel_campaigns WHERE id=?").get(req.params.id);
  if (!c) return res.status(404).json({ error: "Not found" });
  try {
    const result = await sendCampaignBlast(c, req.session.user.username, req.session.user.id);
    logActivity(req, "vessel_campaign_sent", `Manually sent email schedule #${c.id} (${c.subject}) — ${result.sent} sent, ${result.failed} failed`);
    res.json({ ok: true, ...result, campaign: campaignWithMeta(db.prepare("SELECT * FROM vessel_campaigns WHERE id=?").get(c.id)) });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

/* ---------------------------------------------------------------- */
/* CHATBOT — logs what people asked, visible under Admin -> Logs     */
/* ---------------------------------------------------------------- */
app.post("/api/chatbot/query-log", (req, res) => {
  const text = String((req.body && req.body.text) || "").slice(0, 500);
  logActivity(req, "chatbot_query", `${req.session.user.username} asked the chatbot: "${text}"`);
  res.json({ ok: true });
});

app.get("/api/parties", (req, res) => {
  res.json(db.prepare("SELECT * FROM parties ORDER BY name").all());
});
app.post("/api/parties", (req, res) => {
  const { name, contact, email, is_client, is_shipper, is_consignee, is_vendor, agent_name, trn, trade_license } = req.body;
  if (!name) return res.status(400).json({ error: "Party name is required" });
  if (db.prepare("SELECT id FROM parties WHERE name = ? COLLATE NOCASE").get(name)) {
    return res.status(400).json({ error: `A party named "${name}" already exists` });
  }
  const dupErr = duplicateTrnOrLicense(trn, trade_license);
  if (dupErr) return res.status(400).json({ error: dupErr });
  const code = partyCodeSeed();
  const info = db.prepare(`INSERT INTO parties (name, type, code, contact, email, is_client, is_shipper, is_consignee, is_vendor, agent_name, trn, trade_license)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(name, is_vendor ? "Vendor" : "Customer", code, contact || "", email || "",
         is_client?1:0, is_shipper?1:0, is_consignee?1:0, is_vendor?1:0, agent_name || "", trn || "", trade_license || "");
  const newPartyId = info.lastInsertRowid;
  // Auto-link a Receivable sub-account for a client, and/or a Payable sub-account for a vendor —
  // still repointable/renameable afterwards from Chart of Accounts.
  if (is_client) ensurePartyAccount(newPartyId, "client");
  if (is_vendor) ensurePartyAccount(newPartyId, "vendor");
  res.json(db.prepare("SELECT * FROM parties WHERE id=?").get(newPartyId));
});
app.put("/api/parties/:id", (req, res) => {
  const { name, code, contact, email, address, edi_code, is_client, is_shipper, is_consignee, is_vendor, agent_name, trn, trade_license } = req.body;
  const cur = db.prepare("SELECT * FROM parties WHERE id=?").get(req.params.id);
  if (!cur) return res.status(404).json({ error: "Party not found" });
  const dupErr = duplicateTrnOrLicense(trn, trade_license, req.params.id);
  if (dupErr) return res.status(400).json({ error: dupErr });
  db.prepare(`UPDATE parties SET name=?, code=?, contact=?, email=?, address=?, edi_code=?, agent_name=?, trn=?, trade_license=?,
      is_client=?, is_shipper=?, is_consignee=?, is_vendor=? WHERE id=?`)
    .run(name ?? cur.name, code ?? cur.code, contact ?? cur.contact, email ?? cur.email, address ?? cur.address, edi_code ?? cur.edi_code,
         agent_name ?? cur.agent_name, trn ?? cur.trn, trade_license ?? cur.trade_license,
         is_client!==undefined?(is_client?1:0):cur.is_client,
         is_shipper!==undefined?(is_shipper?1:0):cur.is_shipper,
         is_consignee!==undefined?(is_consignee?1:0):cur.is_consignee,
         is_vendor!==undefined?(is_vendor?1:0):cur.is_vendor,
         req.params.id);
  const updated = db.prepare("SELECT * FROM parties WHERE id=?").get(req.params.id);
  if (updated.is_client) ensurePartyAccount(updated.id, "client");
  if (updated.is_vendor) ensurePartyAccount(updated.id, "vendor");
  res.json(updated);
});
app.delete("/api/parties/:id", requireDelete, (req, res) => {
  db.prepare("DELETE FROM parties WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});
app.post("/api/parties/bulk", (req, res) => {
  const rows = Array.isArray(req.body.rows) ? req.body.rows : [];
  let created = 0, skipped = 0;
  const errors = [];
  rows.forEach((r, i) => {
    const name = (r.name || "").trim();
    if (!name) { errors.push(`Row ${i+1}: missing name — skipped`); return; }
    if (db.prepare("SELECT id FROM parties WHERE name = ? COLLATE NOCASE").get(name)) { skipped++; return; }
    const code = partyCodeSeed();
    const isClient = /^y/i.test(String(r.is_client||""));
    const isVendor = /^y/i.test(String(r.is_vendor||""));
    const isShipper = /^y/i.test(String(r.is_shipper||""));
    const isConsignee = /^y/i.test(String(r.is_consignee||""));
    db.prepare(`INSERT INTO parties (name, type, code, contact, email, is_client, is_shipper, is_consignee, is_vendor)
      VALUES (?,?,?,?,?,?,?,?,?)`)
      .run(name, isVendor ? "Vendor" : "Customer", code, r.contact || "", r.email || "",
           isClient?1:0, isShipper?1:0, isConsignee?1:0, isVendor?1:0);
    created++;
  });
  logActivity(req, "parties_bulk_uploaded", `${created} created, ${skipped} duplicate(s) skipped`);
  res.json({ created, skipped, errors });
});

/* ---- Commodities master ---- */
app.get("/api/commodities", (req, res) => {
  res.json(db.prepare("SELECT * FROM commodities ORDER BY name").all());
});
app.post("/api/commodities", (req, res) => {
  const name = (req.body.name || "").trim();
  if (!name) return res.status(400).json({ error: "Commodity name is required" });
  if (db.prepare("SELECT id FROM commodities WHERE name = ? COLLATE NOCASE").get(name)) {
    return res.status(400).json({ error: `Commodity "${name}" already exists` });
  }
  const info = db.prepare("INSERT INTO commodities (name) VALUES (?)").run(name);
  res.json({ id: info.lastInsertRowid, name });
});
app.post("/api/commodities/bulk", (req, res) => {
  const names = (req.body.names || []).map(n => n.trim()).filter(Boolean);
  const ins = db.prepare("INSERT INTO commodities (name) VALUES (?)");
  let added = 0, skipped = 0;
  const tx = db.transaction((rows) => rows.forEach(n => {
    if (db.prepare("SELECT id FROM commodities WHERE name = ? COLLATE NOCASE").get(n)) { skipped++; return; }
    ins.run(n); added++;
  }));
  tx(names);
  res.json({ added, skipped });
});
app.delete("/api/commodities/:id", requireDelete, (req, res) => {
  db.prepare("DELETE FROM commodities WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

/* ---- Charge Codes master (linked to Chart of Accounts) ---- */
app.get("/api/charge-codes", (req, res) => {
  const rows = db.prepare(`
    SELECT cc.*, a.name account_name FROM charge_codes cc LEFT JOIN accounts a ON a.code = cc.account_code
    ORDER BY cc.code`).all();
  res.json(rows);
});
app.post("/api/charge-codes", (req, res) => {
  const code = (req.body.code || "").trim().toUpperCase();
  const name = (req.body.name || "").trim();
  const account_code = req.body.account_code;
  if (!code || !name || !account_code) return res.status(400).json({ error: "Code, name and account are all required" });
  if (db.prepare("SELECT code FROM charge_codes WHERE code = ? COLLATE NOCASE").get(code)) {
    return res.status(400).json({ error: `Charge code "${code}" already exists` });
  }
  if (!db.prepare("SELECT code FROM accounts WHERE code=?").get(account_code)) {
    return res.status(400).json({ error: "That account code doesn't exist in the Chart of Accounts" });
  }
  db.prepare("INSERT INTO charge_codes (code, name, account_code) VALUES (?,?,?)").run(code, name, account_code);
  res.json({ code, name, account_code });
});
app.put("/api/charge-codes/:code", (req, res) => {
  const { name, account_code } = req.body;
  db.prepare("UPDATE charge_codes SET name=?, account_code=? WHERE code=?").run(name, account_code, req.params.code);
  res.json({ ok: true });
});
app.delete("/api/charge-codes/:code", requireDelete, (req, res) => {
  db.prepare("DELETE FROM charge_codes WHERE code=?").run(req.params.code);
  res.json({ ok: true });
});

/* ---------------------------------------------------------------- */
/* TARIFF MASTER — fixed rate cards per container size/type, one series each for            */
/* Export (TRFE-0000/26) and Import (TRFI-0000/26). Once Approved, a Tariff's Charges/Cost   */
/* lines become the auto-suggested rates in Booking's Charges (by client) and Payable/Cost   */
/* (by vendor) sections. An unapproved (or un-approved-again) Tariff is never suggested.      */
/* ---------------------------------------------------------------- */
function tariffCodeSeed(type) {
  return type === "Import" ? nextSeq("TRF-IMP", "TRFI", 4, true) : nextSeq("TRF-EXP", "TRFE", 4, true);
}
function tariffSummary(t) {
  const charges = db.prepare(`
    SELECT tc.*, cc.name AS charge_name, p.name AS client_name, p.code AS client_code
    FROM tariff_charges tc LEFT JOIN charge_codes cc ON cc.code = tc.code LEFT JOIN parties p ON p.id = tc.client_id
    WHERE tc.tariff_id=? ORDER BY tc.id`).all(t.id);
  const costs = db.prepare(`
    SELECT tc.*, p.name AS vendor_name, p.code AS vendor_code
    FROM tariff_costs tc LEFT JOIN parties p ON p.id = tc.vendor_id
    WHERE tc.tariff_id=? ORDER BY tc.id`).all(t.id);
  return { ...t, charges, costs };
}
app.get("/api/tariffs", (req, res) => {
  let rows = db.prepare("SELECT * FROM tariffs ORDER BY id DESC").all();
  if (req.query.type) rows = rows.filter(t => t.type === req.query.type);
  res.json(rows.map(t => {
    const chargeCount = db.prepare("SELECT COUNT(*) c FROM tariff_charges WHERE tariff_id=?").get(t.id).c;
    const costCount = db.prepare("SELECT COUNT(*) c FROM tariff_costs WHERE tariff_id=?").get(t.id).c;
    return { ...t, charge_count: chargeCount, cost_count: costCount };
  }));
});
// ---- Lookups used by Booking to auto-fill a rate from an APPROVED tariff only. ----
// Charges: prefer a rate scoped to this exact client over a "for all clients" (client_id NULL) rate.
// NOTE: these two GETs must be declared before "/api/tariffs/:id" below, or Express would match
// "rate-lookup"/"cost-lookup" as an :id value first and this route would never be reached.
app.get("/api/tariffs/rate-lookup", (req, res) => {
  const { direction, size, code, client } = req.query;
  if (!direction || !size || !code) return res.json({ found: false });
  const clientRow = client ? db.prepare("SELECT id FROM parties WHERE name = ? COLLATE NOCASE").get(client) : null;
  const rows = db.prepare(`
    SELECT tc.* FROM tariff_charges tc JOIN tariffs t ON t.id = tc.tariff_id
    WHERE t.approved=1 AND t.type=? AND tc.size=? AND tc.code=?`).all(direction, size, code);
  if (!rows.length) return res.json({ found: false });
  const specific = clientRow ? rows.find(r => r.client_id === clientRow.id) : null;
  const generic = rows.find(r => !r.client_id);
  const match = specific || generic;
  if (!match) return res.json({ found: false });
  res.json({ found: true, rate: match.rate, currency: match.currency, scope: specific ? "client" : "all-clients" });
});
// Cost: vendor is mandatory on a tariff_costs row, so match is always vendor-specific.
app.get("/api/tariffs/cost-lookup", (req, res) => {
  const { direction, size, vendor } = req.query;
  if (!direction || !size || !vendor) return res.json({ found: false });
  const vendorRow = db.prepare("SELECT id FROM parties WHERE name = ? COLLATE NOCASE").get(vendor);
  if (!vendorRow) return res.json({ found: false });
  const row = db.prepare(`
    SELECT tc.* FROM tariff_costs tc JOIN tariffs t ON t.id = tc.tariff_id
    WHERE t.approved=1 AND t.type=? AND tc.size=? AND tc.vendor_id=?`).get(direction, size, vendorRow.id);
  if (!row) return res.json({ found: false });
  res.json({ found: true, rate: row.rate, currency: row.currency, description: row.description });
});
app.get("/api/tariffs/available-charges", (req, res) => {
  const { direction, client } = req.query;
  if (!direction) return res.json([]);
  const clientRow = client ? db.prepare("SELECT id FROM parties WHERE name = ? COLLATE NOCASE").get(client) : null;
  const rows = db.prepare(`
    SELECT tc.*, cc.name AS charge_name, t.code AS tariff_code, p.name AS client_name
    FROM tariff_charges tc
    JOIN tariffs t ON t.id = tc.tariff_id
    LEFT JOIN charge_codes cc ON cc.code = tc.code
    LEFT JOIN parties p ON p.id = tc.client_id
    WHERE t.approved=1 AND t.type=?
    ORDER BY tc.size, tc.code`).all(direction);
  res.json(rows.filter(r => !r.client_id || (clientRow && r.client_id === clientRow.id)));
});
app.get("/api/tariffs/available-costs", (req, res) => {
  const { direction, vendor } = req.query;
  if (!direction || !vendor) return res.json([]);
  const vendorRow = db.prepare("SELECT id FROM parties WHERE name = ? COLLATE NOCASE").get(vendor);
  if (!vendorRow) return res.json([]);
  const rows = db.prepare(`
    SELECT tc.*, t.code AS tariff_code, p.name AS vendor_name
    FROM tariff_costs tc
    JOIN tariffs t ON t.id = tc.tariff_id
    LEFT JOIN parties p ON p.id = tc.vendor_id
    WHERE t.approved=1 AND t.type=? AND tc.vendor_id=?
    ORDER BY tc.size`).all(direction, vendorRow.id);
  res.json(rows);
});
app.get("/api/tariffs/:id", (req, res) => {
  const t = db.prepare("SELECT * FROM tariffs WHERE id=?").get(req.params.id);
  if (!t) return res.status(404).json({ error: "Tariff not found" });
  res.json(tariffSummary(t));
});
app.post("/api/tariffs", (req, res) => {
  const type = req.body.type === "Import" ? "Import" : "Export";
  const code = tariffCodeSeed(type);
  const info = db.prepare("INSERT INTO tariffs (code, type, name, effective_date) VALUES (?,?,?,?)")
    .run(code, type, req.body.name || "", req.body.effective_date || new Date().toISOString().slice(0, 10));
  logActivity(req, "tariff_created", `Tariff ${code} (${type}) created`);
  res.json(db.prepare("SELECT * FROM tariffs WHERE id=?").get(info.lastInsertRowid));
});
app.put("/api/tariffs/:id", (req, res) => {
  const t = db.prepare("SELECT * FROM tariffs WHERE id=?").get(req.params.id);
  if (!t) return res.status(404).json({ error: "Tariff not found" });
  if (t.approved) return res.status(400).json({ error: "This Tariff is approved and locked — click Un-approve Tariff first if you need to change it." });
  db.prepare("UPDATE tariffs SET name=?, effective_date=? WHERE id=?")
    .run(req.body.name ?? t.name, req.body.effective_date ?? t.effective_date, t.id);
  res.json(tariffSummary(db.prepare("SELECT * FROM tariffs WHERE id=?").get(t.id)));
});
app.post("/api/tariffs/:id/approve", (req, res) => {
  const t = db.prepare("SELECT * FROM tariffs WHERE id=?").get(req.params.id);
  if (!t) return res.status(404).json({ error: "Tariff not found" });
  if (!db.prepare("SELECT id FROM tariff_charges WHERE tariff_id=? UNION SELECT id FROM tariff_costs WHERE tariff_id=?").get(t.id, t.id)) {
    return res.status(400).json({ error: "Add at least one Charge or Cost line before approving this Tariff." });
  }
  db.prepare("UPDATE tariffs SET approved=1 WHERE id=?").run(t.id);
  logActivity(req, "tariff_approved", `Tariff ${t.code} approved`);
  res.json(tariffSummary(db.prepare("SELECT * FROM tariffs WHERE id=?").get(t.id)));
});
app.post("/api/tariffs/:id/unapprove", (req, res) => {
  const t = db.prepare("SELECT * FROM tariffs WHERE id=?").get(req.params.id);
  if (!t) return res.status(404).json({ error: "Tariff not found" });
  db.prepare("UPDATE tariffs SET approved=0 WHERE id=?").run(t.id);
  logActivity(req, "tariff_unapproved", `Tariff ${t.code} un-approved`);
  res.json(tariffSummary(db.prepare("SELECT * FROM tariffs WHERE id=?").get(t.id)));
});
app.delete("/api/tariffs/:id", requireDelete, (req, res) => {
  db.prepare("DELETE FROM tariffs WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

function requireTariffUnlocked(tariffId, res) {
  const t = db.prepare("SELECT * FROM tariffs WHERE id=?").get(tariffId);
  if (!t) { res.status(404).json({ error: "Tariff not found" }); return null; }
  if (t.approved) { res.status(400).json({ error: "This Tariff is approved and locked — click Un-approve Tariff first if you need to change it." }); return null; }
  return t;
}
app.post("/api/tariffs/:id/charges", (req, res) => {
  const t = requireTariffUnlocked(req.params.id, res);
  if (!t) return;
  const { code, size, rate, client_id } = req.body;
  if (!code || !size) return res.status(400).json({ error: "Charge and Size/Type are required" });
  const currency = req.body.currency || "AED";
  const info = db.prepare("INSERT INTO tariff_charges (tariff_id, code, size, rate, currency, client_id) VALUES (?,?,?,?,?,?)")
    .run(t.id, code, size, rate || 0, currency, client_id || null);
  res.json({ id: info.lastInsertRowid });
});
app.put("/api/tariff-charges/:rowId", (req, res) => {
  const row = db.prepare("SELECT * FROM tariff_charges WHERE id=?").get(req.params.rowId);
  if (!row) return res.status(404).json({ error: "Tariff charge line not found" });
  if (!requireTariffUnlocked(row.tariff_id, res)) return;
  const { code, size, rate, client_id } = req.body;
  const currency = req.body.currency || "AED";
  db.prepare("UPDATE tariff_charges SET code=?, size=?, rate=?, currency=?, client_id=? WHERE id=?")
    .run(code ?? row.code, size ?? row.size, rate ?? row.rate, currency, req.body.hasOwnProperty("client_id") ? (client_id || null) : row.client_id, row.id);
  res.json({ ok: true });
});
app.delete("/api/tariff-charges/:rowId", requireDelete, (req, res) => {
  const row = db.prepare("SELECT * FROM tariff_charges WHERE id=?").get(req.params.rowId);
  if (row && !requireTariffUnlocked(row.tariff_id, res)) return;
  db.prepare("DELETE FROM tariff_charges WHERE id=?").run(req.params.rowId);
  res.json({ ok: true });
});
app.post("/api/tariffs/:id/costs", (req, res) => {
  const t = requireTariffUnlocked(req.params.id, res);
  if (!t) return;
  const { description, size, rate, vendor_id } = req.body;
  if (!description || !size) return res.status(400).json({ error: "Charge/description and Size/Type are required" });
  if (!vendor_id) return res.status(400).json({ error: "Select a vendor for this cost rate" });
  const currency = req.body.currency || "AED";
  const info = db.prepare("INSERT INTO tariff_costs (tariff_id, description, size, rate, currency, vendor_id) VALUES (?,?,?,?,?,?)")
    .run(t.id, description, size, rate || 0, currency, vendor_id);
  res.json({ id: info.lastInsertRowid });
});
app.put("/api/tariff-costs/:rowId", (req, res) => {
  const row = db.prepare("SELECT * FROM tariff_costs WHERE id=?").get(req.params.rowId);
  if (!row) return res.status(404).json({ error: "Tariff cost line not found" });
  if (!requireTariffUnlocked(row.tariff_id, res)) return;
  const { description, size, rate, vendor_id } = req.body;
  const currency = req.body.currency || "AED";
  if (!(vendor_id ?? row.vendor_id)) return res.status(400).json({ error: "Select a vendor for this cost rate" });
  db.prepare("UPDATE tariff_costs SET description=?, size=?, rate=?, currency=?, vendor_id=? WHERE id=?")
    .run(description ?? row.description, size ?? row.size, rate ?? row.rate, currency, vendor_id ?? row.vendor_id, row.id);
  res.json({ ok: true });
});
app.delete("/api/tariff-costs/:rowId", requireDelete, (req, res) => {
  const row = db.prepare("SELECT * FROM tariff_costs WHERE id=?").get(req.params.rowId);
  if (row && !requireTariffUnlocked(row.tariff_id, res)) return;
  db.prepare("DELETE FROM tariff_costs WHERE id=?").run(req.params.rowId);
  res.json({ ok: true });
});

// ---- Bulk add: pick several container Size/Types at once and give them all ONE common rate — one
// tariff_charges/tariff_costs row gets created per selected size, all sharing the same rate/currency.
app.post("/api/tariffs/:id/charges/bulk", (req, res) => {
  const t = requireTariffUnlocked(req.params.id, res);
  if (!t) return;
  const { code, sizes, rate, client_id } = req.body;
  if (!code || !Array.isArray(sizes) || !sizes.length) return res.status(400).json({ error: "Charge and at least one Size/Type are required" });
  const currency = req.body.currency || "AED";
  const ins = db.prepare("INSERT INTO tariff_charges (tariff_id, code, size, rate, currency, client_id) VALUES (?,?,?,?,?,?)");
  const tx = db.transaction((sizeList) => sizeList.forEach(size => ins.run(t.id, code, size, rate || 0, currency, client_id || null)));
  tx(sizes);
  res.json({ added: sizes.length });
});
app.post("/api/tariffs/:id/costs/bulk", (req, res) => {
  const t = requireTariffUnlocked(req.params.id, res);
  if (!t) return;
  const { description, sizes, rate, vendor_id } = req.body;
  if (!description || !Array.isArray(sizes) || !sizes.length) return res.status(400).json({ error: "Description and at least one Size/Type are required" });
  if (!vendor_id) return res.status(400).json({ error: "Select a vendor for this cost rate" });
  const currency = req.body.currency || "AED";
  const ins = db.prepare("INSERT INTO tariff_costs (tariff_id, description, size, rate, currency, vendor_id) VALUES (?,?,?,?,?,?)");
  const tx = db.transaction((sizeList) => sizeList.forEach(size => ins.run(t.id, description, size, rate || 0, currency, vendor_id)));
  tx(sizes);
  res.json({ added: sizes.length });
});

// ---- "Apply Tariff" / "Remove Tariff" in Booking's Charges & Payable/Cost sections — this is a
// deliberate, explicit action (a button click), never an automatic/silent auto-fill. Applying adds
// one job_charges/job_costs row per selected Tariff line, tagged with its tariff_charge_id/
// tariff_cost_id so "Remove Tariff" can find and undo exactly (and only) those rows.
function currencyExRate(currency) {
  if (currency === "AED") return 1;
  const row = db.prepare("SELECT exchange_rate FROM currencies WHERE code=?").get(currency);
  return row ? row.exchange_rate : 1;
}
app.post("/api/jobs/:id/apply-tariff-charges", (req, res) => {
  const job = db.prepare("SELECT * FROM jobs WHERE id=?").get(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found" });
  if (!job.booking_saved) return res.status(400).json({ error: "Save Booking Info first — charges can't be added until the booking has been saved." });
  if (job.charges_approved) return res.status(400).json({ error: "Charges are approved and locked — click Un-approve Charges first." });
  const ids = req.body.ids || [];
  if (!ids.length) return res.status(400).json({ error: "Select at least one Tariff charge line to apply" });
  const ins = db.prepare("INSERT INTO job_charges (job_id, code, size, rate, currency, exchange_rate, tariff_charge_id) VALUES (?,?,?,?,?,?,?)");
  let added = 0;
  ids.forEach(id => {
    const tc = db.prepare(`SELECT tc.* FROM tariff_charges tc JOIN tariffs t ON t.id=tc.tariff_id WHERE tc.id=? AND t.approved=1`).get(id);
    if (!tc) return;
    ins.run(job.id, tc.code, tc.size, tc.rate, tc.currency, currencyExRate(tc.currency), tc.id);
    added++;
  });
  if (!added) return res.status(400).json({ error: "None of the selected Tariff lines could be applied (they may no longer be approved)" });
  logActivity(req, "tariff_applied_charges", `Job ${req.params.id} — ${added} Tariff charge line(s) applied`);
  res.json({ added });
});
app.post("/api/jobs/:id/remove-tariff-charges", (req, res) => {
  const job = db.prepare("SELECT * FROM jobs WHERE id=?").get(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found" });
  if (job.charges_approved) return res.status(400).json({ error: "Charges are approved and locked — click Un-approve Charges first." });
  const info = db.prepare("DELETE FROM job_charges WHERE job_id=? AND tariff_charge_id IS NOT NULL").run(req.params.id);
  logActivity(req, "tariff_removed_charges", `Job ${req.params.id} — ${info.changes} Tariff charge line(s) removed`);
  res.json({ removed: info.changes });
});
app.post("/api/jobs/:id/apply-tariff-costs", (req, res) => {
  const job = db.prepare("SELECT * FROM jobs WHERE id=?").get(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found" });
  if (!job.booking_saved) return res.status(400).json({ error: "Save Booking Info first — cost/payable lines can't be added until the booking has been saved." });
  const { ids, vendor } = req.body;
  if (!vendor) return res.status(400).json({ error: "Select a vendor first" });
  if (!ids || !ids.length) return res.status(400).json({ error: "Select at least one Tariff cost line to apply" });
  ensurePartyRole(vendor, "is_vendor");
  const equipSizes = equipmentSizesForJob(job.id); // qty comes from Equipment, same as a manual Qty × Rate cost line
  const ins = db.prepare(`INSERT INTO job_costs (job_id, vendor, description, size, qty, rate, amount, currency, exchange_rate, expense_account, bill_type, tariff_cost_id)
    VALUES (?,?,?,?,?,?,0,?,?,?, 'Regular', ?)`);
  let added = 0;
  ids.forEach(id => {
    const tc = db.prepare(`SELECT tc.* FROM tariff_costs tc JOIN tariffs t ON t.id=tc.tariff_id WHERE tc.id=? AND t.approved=1`).get(id);
    if (!tc) return;
    const qty = equipSizes[tc.size] || 0;
    ins.run(job.id, vendor, tc.description, tc.size, qty, tc.rate, tc.currency, currencyExRate(tc.currency), "5020", tc.id);
    added++;
  });
  if (!added) return res.status(400).json({ error: "None of the selected Tariff lines could be applied (they may no longer be approved)" });
  logActivity(req, "tariff_applied_costs", `Job ${req.params.id} — ${added} Tariff cost line(s) applied for ${vendor}`);
  res.json({ added });
});
app.post("/api/jobs/:id/remove-tariff-costs", (req, res) => {
  // Only removes still-draft lines (not yet part of a generated bill) — a billed line is locked
  // the same way a manually-added one is, and must be undone by deleting the bill instead.
  const info = db.prepare("DELETE FROM job_costs WHERE job_id=? AND tariff_cost_id IS NOT NULL AND bill_id IS NULL").run(req.params.id);
  logActivity(req, "tariff_removed_costs", `Job ${req.params.id} — ${info.changes} Tariff cost line(s) removed`);
  res.json({ removed: info.changes });
});


/* ---- Ports master (worldwide) ---- */
function findPortByName(name) {
  if (!name) return null;
  return db.prepare("SELECT * FROM ports WHERE name = ? COLLATE NOCASE").get(name);
}
function portNameForLocode(locode) {
  if (!locode) return "";
  const p = db.prepare("SELECT name FROM ports WHERE locode = ? COLLATE NOCASE").get(locode);
  return p ? p.name : locode;
}
app.get("/api/ports", (req, res) => {
  res.json(db.prepare("SELECT * FROM ports ORDER BY name").all());
});
app.post("/api/ports", (req, res) => {
  const name = (req.body.name || "").trim().toUpperCase();
  const { country, locode } = req.body;
  if (!name) return res.status(400).json({ error: "Port name is required" });
  if (findPortByName(name)) return res.status(400).json({ error: `Port "${name}" already exists` });
  const info = db.prepare("INSERT INTO ports (name, country, locode) VALUES (?,?,?)").run(name, country || "", locode || "");
  res.json({ id: info.lastInsertRowid, name, country, locode });
});
app.post("/api/charge-codes/bulk", (req, res) => {
  const rows = req.body.rows || []; // [{code, name, account_code}]
  let added = 0;
  const skipped = [];
  const ins = db.prepare("INSERT INTO charge_codes (code, name, account_code) VALUES (?,?,?)");
  rows.forEach(r => {
    const code = String(r.code || "").trim().toUpperCase();
    const name = String(r.name || "").trim();
    const account_code = String(r.account_code || "").trim();
    if (!code || !name || !account_code) { skipped.push({ code: r.code, reason: "Missing code, name, or account" }); return; }
    if (db.prepare("SELECT code FROM charge_codes WHERE code = ? COLLATE NOCASE").get(code)) { skipped.push({ code, reason: "Already exists" }); return; }
    if (!db.prepare("SELECT code FROM accounts WHERE code=?").get(account_code)) { skipped.push({ code, reason: `Account "${account_code}" not found` }); return; }
    ins.run(code, name, account_code);
    added++;
  });
  logActivity(req, "charge_codes_bulk_uploaded", `Bulk uploaded ${added} charge code(s), ${skipped.length} skipped`);
  res.json({ added, skipped });
});
app.post("/api/ports/bulk", (req, res) => {
  const rows = req.body.rows || []; // [{name, country, locode}]
  const ins = db.prepare("INSERT INTO ports (name, country, locode) VALUES (?,?,?)");
  let added = 0, skipped = 0;
  const tx = db.transaction((rows) => rows.forEach(r => {
    const name = (r.name || "").trim().toUpperCase();
    if (!name || findPortByName(name)) { skipped++; return; }
    ins.run(name, r.country || "", r.locode || "");
    added++;
  }));
  tx(rows);
  res.json({ added, skipped });
});
app.delete("/api/ports/:id", requireDelete, (req, res) => {
  db.prepare("DELETE FROM ports WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

app.get("/api/users", (req, res) => {
  const users = db.prepare("SELECT id, name, username, role, modules, active, can_delete, can_export, can_import, can_approve, chatbot_only, locked, failed_attempts FROM users ORDER BY id").all();
  res.json(users);
});
app.post("/api/users", (req, res) => {
  const { name, username, role, password, can_delete, can_export, can_import, can_approve, chatbot_only } = req.body;
  let { modules } = req.body;
  if (!password || password.length < 4) return res.status(400).json({ error: "Password must be at least 4 characters" });
  if (db.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE").get(username)) {
    return res.status(400).json({ error: "That username already exists" });
  }
  // A chatbot-only account is locked to ONLY the chatbot module, regardless of what was ticked in the form.
  if (chatbot_only) modules = ["chatbot"];
  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare(`INSERT INTO users (name, username, role, modules, active, password_hash, can_delete, can_export, can_import, can_approve, chatbot_only)
    VALUES (?,?,?,?,1,?,?,?,?,?,?)`)
    .run(name, username, role, (modules || []).join(","), hash, can_delete ? 1 : 0, can_export ? 1 : 0, can_import ? 1 : 0, can_approve ? 1 : 0, chatbot_only ? 1 : 0);
  const u = db.prepare("SELECT id, name, username, role, modules, active, can_delete, can_export, can_import, can_approve, chatbot_only FROM users WHERE id=?").get(info.lastInsertRowid);
  logActivity(req, "user_created", `Created user ${username} (${role})${chatbot_only ? " — chatbot-only access" : ""}`);
  res.json(u);
});
app.put("/api/users/:id", (req, res) => {
  const cur = db.prepare("SELECT * FROM users WHERE id=?").get(req.params.id);
  if (!cur) return res.status(404).json({ error: "User not found" });
  const { name, role, password, can_delete, can_export, can_import, can_approve, chatbot_only } = req.body;
  let { modules } = req.body;
  if (chatbot_only) modules = ["chatbot"];
  const modulesStr = Array.isArray(modules) ? modules.join(",") : cur.modules;

  if (password) {
    if (password.length < 4) return res.status(400).json({ error: "Password must be at least 4 characters" });
    const hash = bcrypt.hashSync(password, 10);
    db.prepare(`UPDATE users SET name=?, role=?, modules=?, password_hash=?, can_delete=?, can_export=?, can_import=?, can_approve=?, chatbot_only=? WHERE id=?`)
      .run(name ?? cur.name, role ?? cur.role, modulesStr, hash,
           can_delete!==undefined?(can_delete?1:0):cur.can_delete,
           can_export!==undefined?(can_export?1:0):cur.can_export,
           can_import!==undefined?(can_import?1:0):cur.can_import,
           can_approve!==undefined?(can_approve?1:0):cur.can_approve,
           chatbot_only!==undefined?(chatbot_only?1:0):cur.chatbot_only,
           req.params.id);
  } else {
    db.prepare(`UPDATE users SET name=?, role=?, modules=?, can_delete=?, can_export=?, can_import=?, can_approve=?, chatbot_only=? WHERE id=?`)
      .run(name ?? cur.name, role ?? cur.role, modulesStr,
           can_delete!==undefined?(can_delete?1:0):cur.can_delete,
           can_export!==undefined?(can_export?1:0):cur.can_export,
           can_import!==undefined?(can_import?1:0):cur.can_import,
           can_approve!==undefined?(can_approve?1:0):cur.can_approve,
           chatbot_only!==undefined?(chatbot_only?1:0):cur.chatbot_only,
           req.params.id);
  }
  logActivity(req, "user_edited", `Edited user ${cur.username} — rights updated`);
  res.json(db.prepare("SELECT id, name, username, role, modules, active, can_delete, can_export, can_import, can_approve, chatbot_only FROM users WHERE id=?").get(req.params.id));
});
app.post("/api/users/:id/toggle", (req, res) => {
  const u = db.prepare("SELECT * FROM users WHERE id=?").get(req.params.id);
  db.prepare("UPDATE users SET active=? WHERE id=?").run(u.active ? 0 : 1, req.params.id);
  res.json(db.prepare("SELECT id, name, username, role, modules, active, can_delete, can_export, can_import, can_approve, chatbot_only, locked, failed_attempts FROM users WHERE id=?").get(req.params.id));
});
app.post("/api/users/:id/unlock", (req, res) => {
  const u = db.prepare("SELECT * FROM users WHERE id=?").get(req.params.id);
  if (!u) return res.status(404).json({ error: "User not found" });
  db.prepare("UPDATE users SET locked=0, failed_attempts=0 WHERE id=?").run(req.params.id);
  logActivity(req, "account_unlocked", `${u.username} — account unblocked by admin`);
  res.json(db.prepare("SELECT id, name, username, role, modules, active, can_delete, can_export, can_import, can_approve, chatbot_only, locked, failed_attempts FROM users WHERE id=?").get(req.params.id));
});
app.post("/api/users/:id/toggle-delete", requireDelete, (req, res) => {
  const u = db.prepare("SELECT * FROM users WHERE id=?").get(req.params.id);
  db.prepare("UPDATE users SET can_delete=? WHERE id=?").run(u.can_delete ? 0 : 1, req.params.id);
  res.json(db.prepare("SELECT id, name, username, role, modules, active, can_delete FROM users WHERE id=?").get(req.params.id));
});
app.delete("/api/users/:id", requireDelete, (req, res) => {
  db.prepare("DELETE FROM users WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

/* ---------------------------------------------------------------- */
/* REPORTS                                                            */
/* ---------------------------------------------------------------- */
app.get("/api/reports/job-list", (req, res) => {
  const jobs = db.prepare("SELECT * FROM jobs ORDER BY id DESC").all();
  res.json(jobs.map(jobSummary));
});

app.get("/api/reports/job-pl", (req, res) => {
  const jobs = db.prepare("SELECT * FROM jobs ORDER BY id DESC").all();
  res.json(jobs.map(j => {
    const inv = db.prepare("SELECT * FROM invoices WHERE job_id=?").get(j.id);
    const cost = costForJobIds([j.id]);
    const revenue = inv ? inv.amount : 0;
    return { job_no: j.job_no, client: j.client, revenue, cost, profit: revenue - cost };
  }));
});

app.get("/api/reports/job-balancing", (req, res) => {
  const jobs = db.prepare("SELECT * FROM jobs ORDER BY id DESC").all();
  res.json(jobs.map(j => {
    const inv = db.prepare("SELECT * FROM invoices WHERE job_id=?").get(j.id);
    const cost = costForJobIds([j.id]);
    const paid = costPaidForJobIds([j.id]);
    const invoiced = inv ? inv.amount : 0;
    const received = inv ? inv.settled_amount : 0;
    return {
      job_no: j.job_no, client: j.client, invoiced, received,
      ar_outstanding: invoiced - received, billed: cost, paid, ap_outstanding: cost - paid
    };
  }));
});

app.get("/api/reports/client-exposure", (req, res) => {
  const rows = db.prepare(`
    SELECT client, COALESCE(SUM(amount),0) invoiced, COALESCE(SUM(settled_amount),0) received
    FROM invoices i JOIN jobs j ON j.id=i.job_id GROUP BY client ORDER BY (invoiced-received) DESC`).all();
  res.json(rows.map(r => ({ ...r, exposure: r.invoiced - r.received })));
});

app.get("/api/reports/job-statistics", (req, res) => {
  const totalJobs = db.prepare("SELECT COUNT(*) c FROM jobs").get().c;
  const approvedJobs = db.prepare("SELECT COUNT(*) c FROM jobs WHERE job_approved=1").get().c;
  const totalContainers = db.prepare("SELECT COALESCE(SUM(qty),0) t FROM job_equipment").get().t;
  const totalRevenue = db.prepare("SELECT COALESCE(SUM(amount),0) t FROM invoices").get().t;
  const totalOutstanding = db.prepare("SELECT COALESCE(SUM(amount-settled_amount),0) t FROM invoices").get().t;
  res.json({ totalJobs, approvedJobs, totalContainers, totalRevenue, totalOutstanding,
    avgRevenue: totalJobs ? totalRevenue / totalJobs : 0 });
});

app.get("/api/reports/charges-wise-job", (req, res) => {
  const jobs = db.prepare("SELECT * FROM jobs").all();
  const rows = [];
  jobs.forEach(j => chargeLinesForJob(j.id).forEach(l => rows.push({ job_no: j.job_no, ...l })));
  res.json(rows);
});

app.get("/api/reports/job-containers", (req, res) => {
  const rows = db.prepare(`
    SELECT j.job_no, c.no, c.seal, c.size, c.weight
    FROM job_containers c JOIN jobs j ON j.id = c.job_id ORDER BY j.id DESC`).all();
  res.json(rows);
});

app.get("/api/reports/bl-release-status", (req, res) => {
  const rows = db.prepare(`
    SELECT j.job_no, j.client, b.hbl, b.mbl, b.release_status, b.handover_type
    FROM jobs j LEFT JOIN job_bl b ON b.job_id = j.id ORDER BY j.id DESC`).all();
  res.json(rows);
});

app.get("/api/reports/party-soa/:client", (req, res) => {
  const client = req.params.client;
  const invoices = db.prepare(`
    SELECT i.date, 'Invoice' type, i.txn ref, i.amount debit, 0 credit
    FROM invoices i JOIN jobs j ON j.id=i.job_id WHERE j.client=?`).all(client);
  const receipts = db.prepare(`
    SELECT v.date, 'Receipt' type, v.no ref, 0 debit, vl.credit credit
    FROM vouchers v JOIN voucher_lines vl ON vl.voucher_id=v.id
    WHERE v.source='receipt' AND vl.account_code='1000' AND v.narration LIKE '%' || ? || '%'`).all(client);
  const entries = [...invoices, ...receipts].sort((a,b)=>String(a.date).localeCompare(String(b.date)));
  let running = 0;
  res.json(entries.map(e => { running += e.debit - e.credit; return { ...e, balance: running }; }));
});

app.get("/api/reports/party-audit/:vendor", (req, res) => {
  const vendor = req.params.vendor;
  const bills = db.prepare(`SELECT date, 'Bill' type, bill_no ref, 0 debit, amount credit FROM ap_bills WHERE vendor=?`).all(vendor);
  const payments = db.prepare(`
    SELECT v.date, 'Payment' type, v.no ref, vl.debit debit, 0 credit
    FROM vouchers v JOIN voucher_lines vl ON vl.voucher_id=v.id
    WHERE v.source='payment' AND vl.account_code='2000' AND v.narration LIKE '%' || ? || '%'`).all(vendor);
  const entries = [...bills, ...payments].sort((a,b)=>String(a.date).localeCompare(String(b.date)));
  let running = 0;
  res.json(entries.map(e => { running += e.credit - e.debit; return { ...e, balance: running }; }));
});

/* ---------------------------------------------------------------- */
/* OPENING BALANCES — one-time migration upload from the old system   */
/* ---------------------------------------------------------------- */
function openingEquityAccount() {
  const code = "3900";
  if (!db.prepare("SELECT code FROM accounts WHERE code=?").get(code)) {
    db.prepare("INSERT INTO accounts (code, name, type) VALUES (?,?,?)").run(code, "Opening Balance Equity", "Equity");
  }
  return code;
}
// An advance paid to a vendor sits here (an asset — money we're owed back or that will offset a
// future bill) rather than hitting an expense account immediately.
function advancesToVendorsAccount() {
  const code = "1050";
  if (!db.prepare("SELECT code FROM accounts WHERE code=?").get(code)) {
    db.prepare("INSERT INTO accounts (code, name, type) VALUES (?,?,?)").run(code, "Advances to Vendors", "Asset");
  }
  return code;
}

// Chart-of-Accounts-wise: upload a full (or partial) trial balance as of a cut-off date.
// Every account code must already exist in the Chart of Accounts. If the sheet's debits and
// credits don't already balance, the difference is posted to "Opening Balance Equity" so the
// voucher still balances — this is normal when a partial trial balance is uploaded.
app.post("/api/opening-balances/accounts", (req, res) => {
  const rows = Array.isArray(req.body.rows) ? req.body.rows : [];
  const date = req.body.date || getSetting("opening_balance_date", `20${currentFY()}-01-01`);
  if (!rows.length) return res.status(400).json({ error: "No rows found in the upload" });

  const lines = [];
  const errors = [];
  let drTotal = 0, crTotal = 0;
  rows.forEach((r, i) => {
    const code = String(r.code || "").trim();
    const debit = Number(r.debit || 0), credit = Number(r.credit || 0);
    if (!code) { errors.push(`Row ${i + 2}: missing account code`); return; }
    if (!db.prepare("SELECT code FROM accounts WHERE code=?").get(code)) {
      errors.push(`Row ${i + 2}: account code "${code}" does not exist in the Chart of Accounts — add it first`);
      return;
    }
    if (!debit && !credit) return;
    lines.push({ account: code, debit, credit });
    drTotal += debit; crTotal += credit;
  });
  if (errors.length) return res.status(400).json({ error: errors.join("; ") });
  if (!lines.length) return res.status(400).json({ error: "No non-zero opening balances found in the upload" });

  const diff = Math.round((drTotal - crTotal) * 100) / 100;
  if (Math.abs(diff) > 0.01) {
    const equityCode = openingEquityAccount();
    if (diff > 0) lines.push({ account: equityCode, debit: 0, credit: diff });
    else lines.push({ account: equityCode, debit: -diff, credit: 0 });
  }
  const v = postVoucher({ date, narration: `Opening balances upload (Chart of Accounts) — ${lines.length} account(s)`, source: "opening", lines });
  logActivity(req, "opening_balances_uploaded", `Chart-of-accounts opening balances uploaded — voucher ${v.no}, ${lines.length} line(s)`);
  res.json({ ok: true, voucher: v, lines_posted: lines.length });
});

// Customer-wise: each row becomes a legacy "Opening Balance" job + invoice for that client (so it
// shows up normally in Job List / Receivables / Client Receipt), backed by a JV to Accounts Receivable.
app.post("/api/opening-balances/customers", (req, res) => {
  const rows = Array.isArray(req.body.rows) ? req.body.rows : [];
  const date = req.body.date || getSetting("opening_balance_date", `20${currentFY()}-01-01`);
  if (!rows.length) return res.status(400).json({ error: "No rows found in the upload" });

  const equityCode = openingEquityAccount();
  let created = 0;
  const errors = [];
  rows.forEach((r, i) => {
    const client = String(r.client || "").trim();
    const amount = Number(r.amount || 0);
    if (!client) { errors.push(`Row ${i + 2}: missing client name`); return; }
    if (!amount) return; // zero balance — nothing to migrate

    // Auto-create the party (tagged Client) if it doesn't already exist.
    let party = db.prepare("SELECT * FROM parties WHERE name = ? COLLATE NOCASE").get(client);
    if (!party) {
      const code = partyCodeSeed();
      db.prepare("INSERT INTO parties (name, type, code, is_client) VALUES (?,?,?,1)").run(client, "Customer", code);
    } else {
      ensurePartyRole(client, "is_client");
    }

    const jobNo = nextSeq("OB", "OB", 5, true);
    const jobInfo = db.prepare(`INSERT INTO jobs (job_no, job_date, job_type, client, direction, booking_approved, charges_approved, job_approved)
      VALUES (?,?,?,?,?,1,1,1)`).run(jobNo, date, "Opening Balance", client, "Export");
    const jobId = jobInfo.lastInsertRowid;
    db.prepare("INSERT INTO job_bl (job_id, hbl) VALUES (?,?)").run(jobId, jobNo);

    db.prepare(`INSERT INTO invoices (job_id, txn, date, currency, amount, settled_amount) VALUES (?,?,?,?,?,0)`)
      .run(jobId, jobNo, date, "AED", Math.abs(amount));

    const lines = amount > 0
      ? [{ account: "1000", debit: amount, credit: 0 }, { account: equityCode, debit: 0, credit: amount }]
      : [{ account: equityCode, debit: -amount, credit: 0 }, { account: "1000", debit: 0, credit: -amount }];
    postVoucher({ date, narration: `Opening balance — ${client} (${jobNo})`, source: "opening", lines });
    created++;
  });
  if (errors.length && !created) return res.status(400).json({ error: errors.join("; ") });
  logActivity(req, "opening_balances_uploaded", `Customer-wise opening balances uploaded — ${created} client(s)`);
  res.json({ ok: true, created, errors });
});
/* ---------------------------------------------------------------- */
/* SETTINGS (Financial Year, SMTP, Company Profile)                   */
/* ---------------------------------------------------------------- */
app.get("/api/settings", (req, res) => {
  res.json({
    financial_year: getSetting("financial_year", new Date().getFullYear().toString().slice(-2)),
    smtp_host: getSetting("smtp_host", ""),
    smtp_port: getSetting("smtp_port", "587"),
    smtp_secure: getSetting("smtp_secure", "false"),
    smtp_user: getSetting("smtp_user", ""),
    smtp_pass_set: !!getSetting("smtp_pass", ""),
    smtp_from: getSetting("smtp_from", ""),
    company_name: getSetting("company_name", "Harbor Desk Shipping LLC"),
    company_address: getSetting("company_address", ""),
    company_email: getSetting("company_email", ""),
    company_phone: getSetting("company_phone", ""),
    company_logo: getSetting("company_logo", ""), // data: URL or hosted image URL
    opening_balance_date: getSetting("opening_balance_date", `20${currentFY()}-01-01`),
  });
});
app.put("/api/settings", (req, res) => {
  const b = req.body;
  if (b.financial_year !== undefined) setSetting("financial_year", String(b.financial_year));
  if (b.smtp_host !== undefined) setSetting("smtp_host", b.smtp_host);
  if (b.smtp_port !== undefined) setSetting("smtp_port", String(b.smtp_port));
  if (b.smtp_secure !== undefined) setSetting("smtp_secure", String(!!b.smtp_secure));
  if (b.smtp_user !== undefined) setSetting("smtp_user", b.smtp_user);
  if (b.smtp_pass) setSetting("smtp_pass", b.smtp_pass); // only overwrite if a new one was actually typed
  if (b.smtp_from !== undefined) setSetting("smtp_from", b.smtp_from);
  if (b.company_name !== undefined) setSetting("company_name", b.company_name);
  if (b.company_address !== undefined) setSetting("company_address", b.company_address);
  if (b.company_email !== undefined) setSetting("company_email", b.company_email);
  if (b.company_phone !== undefined) setSetting("company_phone", b.company_phone);
  if (b.company_logo !== undefined) setSetting("company_logo", b.company_logo);
  if (b.opening_balance_date !== undefined) setSetting("opening_balance_date", b.opening_balance_date);
  logActivity(req, "settings_updated", "Settings updated");
  res.json({ ok: true });
});
// Public (no-module-restriction) read of just the company profile — the invoice page needs this
// for its header/footer and any logged-in user should be able to see it, regardless of module.
app.get("/api/company-profile", (req, res) => {
  res.json({
    name: getSetting("company_name", "Harbor Desk Shipping LLC"),
    address: getSetting("company_address", ""),
    email: getSetting("company_email", ""),
    phone: getSetting("company_phone", ""),
    logo: getSetting("company_logo", ""),
  });
});

/* ---------------------------------------------------------------- */
/* CURRENCY & EXCHANGE RATE MASTER                                    */
/* A simple master table: Add / Edit / Delete a currency's fixed      */
/* exchange rate to AED, with an "applicable from" date and notes.    */
/* Charges/Costs/Payables/Invoices still store their OWN exchange     */
/* rate at the moment they were entered (so past postings never move */
/* when this master rate changes) — this table is just the lookup    */
/* source that pre-fills the rate field when a currency is picked.    */
/* ---------------------------------------------------------------- */
app.get("/api/currencies", (req, res) => {
  res.json(db.prepare("SELECT * FROM currencies ORDER BY code").all());
});
app.post("/api/currencies", (req, res) => {
  const code = (req.body.code || "").trim().toUpperCase();
  const name = (req.body.name || "").trim();
  const exchange_rate = Number(req.body.exchange_rate);
  const applicable_from = req.body.applicable_from || new Date().toISOString().slice(0, 10);
  const notes = req.body.notes || "";
  if (!code) return res.status(400).json({ error: "Currency code is required (e.g. USD, EUR)" });
  if (!exchange_rate || exchange_rate <= 0) return res.status(400).json({ error: "Enter a valid exchange rate to AED" });
  if (db.prepare("SELECT code FROM currencies WHERE code=?").get(code)) {
    return res.status(400).json({ error: `Currency "${code}" already exists — edit it instead of adding a duplicate.` });
  }
  db.prepare("INSERT INTO currencies (code, name, exchange_rate, applicable_from, notes) VALUES (?,?,?,?,?)")
    .run(code, name, exchange_rate, applicable_from, notes);
  logActivity(req, "currency_added", `Currency ${code} added — rate ${exchange_rate}`);
  res.json(db.prepare("SELECT * FROM currencies WHERE code=?").get(code));
});
app.put("/api/currencies/:code", (req, res) => {
  const code = req.params.code.toUpperCase();
  const cur = db.prepare("SELECT * FROM currencies WHERE code=?").get(code);
  if (!cur) return res.status(404).json({ error: "Currency not found" });
  const name = req.body.name ?? cur.name;
  const exchange_rate = req.body.exchange_rate !== undefined ? Number(req.body.exchange_rate) : cur.exchange_rate;
  const applicable_from = req.body.applicable_from ?? cur.applicable_from;
  const notes = req.body.notes ?? cur.notes;
  if (!exchange_rate || exchange_rate <= 0) return res.status(400).json({ error: "Enter a valid exchange rate to AED" });
  db.prepare("UPDATE currencies SET name=?, exchange_rate=?, applicable_from=?, notes=?, updated_at=datetime('now') WHERE code=?")
    .run(name, exchange_rate, applicable_from, notes, code);
  logActivity(req, "currency_updated", `Currency ${code} updated — rate ${exchange_rate}`);
  res.json(db.prepare("SELECT * FROM currencies WHERE code=?").get(code));
});
app.delete("/api/currencies/:code", requireDelete, (req, res) => {
  const code = req.params.code.toUpperCase();
  if (code === "AED") return res.status(400).json({ error: "AED is the base currency and can't be deleted." });
  const reason = (req.body && req.body.reason || "").trim();
  if (!reason) return res.status(400).json({ error: "A reason is required to delete a currency" });
  db.prepare("DELETE FROM currencies WHERE code=?").run(code);
  logActivity(req, "currency_deleted", `Currency ${code} deleted — reason: ${reason}`);
  res.json({ ok: true });
});

/* ---------------------------------------------------------------- */
/* ACTIVITY & EMAIL LOGS                                              */
/* ---------------------------------------------------------------- */
app.get("/api/activity-logs", (req, res) => {
  res.json(db.prepare("SELECT * FROM activity_logs ORDER BY id DESC LIMIT 300").all());
});
app.get("/api/email-logs", (req, res) => {
  res.json(db.prepare("SELECT * FROM email_logs ORDER BY id DESC LIMIT 300").all());
});

// vessel/voyage combos that currently have jobs, for the EDI picker
app.get("/api/edi/manifest-options", (req, res) => {
  const rows = db.prepare(`
    SELECT DISTINCT j.vessel_id, v.name vessel_name, j.voyage_id, voy.no voyage_no
    FROM jobs j JOIN vessels v ON v.id=j.vessel_id JOIN voyages voy ON voy.id=j.voyage_id
    WHERE j.vessel_id IS NOT NULL AND j.voyage_id IS NOT NULL
    ORDER BY v.name, voy.no`).all();
  res.json(rows);
});

function findPartyByName(name) {
  if (!name) return null;
  return db.prepare("SELECT * FROM parties WHERE name = ? COLLATE NOCASE").get(name);
}

// Build the "missing fields" list for one job, mirroring what the real PEDI format expects.
function ediMissingForJob(job) {
  const missing = [];
  if (!job.incoterm) missing.push({ field: "incoterm", label: "Term (Incoterm, e.g. CFR)" });
  if (!job.ld_term) missing.push({ field: "ld_term", label: "LD Term (e.g. CY/CY)" });
  if (!job.consignee) missing.push({ field: "consignee", label: "Consignee name" });
  if (!job.consignee_address) missing.push({ field: "consignee_address", label: "Consignee address" });
  const shipperParty = findPartyByName(job.shipper);
  if (!shipperParty) missing.push({ field: "shipper_party", label: `Shipper "${job.shipper || '—'}" not found in Customers & Vendors — add it with a code & address` });
  else {
    if (!shipperParty.edi_code) missing.push({ field: "shipper_code", label: "Shipper EDI code (numeric)" });
    if (!shipperParty.address) missing.push({ field: "shipper_address", label: "Shipper address" });
  }
  return missing;
}

app.get("/api/edi/prepare/:vesselId/:voyageId", (req, res) => {
  const { vesselId, voyageId } = req.params;
  const vessel = db.prepare("SELECT * FROM vessels WHERE id=?").get(vesselId);
  const voyage = db.prepare("SELECT * FROM voyages WHERE id=?").get(voyageId);
  if (!vessel || !voyage) return res.status(404).json({ error: "Vessel/voyage not found" });
  let manifest = db.prepare("SELECT * FROM manifests WHERE vessel_id=? AND voyage_id=?").get(vesselId, voyageId);
  if (!manifest) manifest = { vessel_id: Number(vesselId), voyage_id: Number(voyageId), overseas_agent: "", reference: "", project_code: "" };

  const jobs = db.prepare("SELECT * FROM jobs WHERE vessel_id=? AND voyage_id=?").all(vesselId, voyageId);
  const jobsOut = jobs.map(j => {
    const bl = db.prepare("SELECT * FROM job_bl WHERE job_id=?").get(j.id) || {};
    const containers = db.prepare("SELECT * FROM job_containers WHERE job_id=?").all(j.id);
    const shipperParty = findPartyByName(j.shipper);
    return {
      id: j.id, job_no: j.job_no, client: j.client, shipper: j.shipper, consignee: j.consignee,
      consignee_address: j.consignee_address, pol: j.pol, pod: j.pod, final_dest: j.final_dest,
      commodity: j.commodity, incoterm: j.incoterm, ld_term: j.ld_term, freight_type: j.freight_type,
      hbl: bl.hbl, mbl: bl.mbl, job_date: j.job_date,
      shipper_party: shipperParty,
      containers,
      missing: ediMissingForJob(j)
    };
  });

  res.json({ vessel, voyage, manifest, jobs: jobsOut });
});

app.put("/api/edi/manifest/:vesselId/:voyageId", (req, res) => {
  const { vesselId, voyageId } = req.params;
  const { overseas_agent, reference, project_code } = req.body;
  const exists = db.prepare("SELECT id FROM manifests WHERE vessel_id=? AND voyage_id=?").get(vesselId, voyageId);
  if (exists) {
    db.prepare("UPDATE manifests SET overseas_agent=?, reference=?, project_code=? WHERE id=?")
      .run(overseas_agent, reference, project_code, exists.id);
  } else {
    db.prepare("INSERT INTO manifests (vessel_id, voyage_id, overseas_agent, reference, project_code) VALUES (?,?,?,?,?)")
      .run(vesselId, voyageId, overseas_agent, reference, project_code);
  }
  res.json(db.prepare("SELECT * FROM manifests WHERE vessel_id=? AND voyage_id=?").get(vesselId, voyageId));
});

// Fill in the EDI-specific fields that are missing on a job (Term, LD Term, Consignee, Consignee Address)
app.put("/api/edi/job/:id", (req, res) => {
  const { incoterm, ld_term, consignee, consignee_address } = req.body;
  const cur = db.prepare("SELECT * FROM jobs WHERE id=?").get(req.params.id);
  if (!cur) return res.status(404).json({ error: "Job not found" });
  db.prepare("UPDATE jobs SET incoterm=?, ld_term=?, consignee=?, consignee_address=? WHERE id=?").run(
    incoterm ?? cur.incoterm, ld_term ?? cur.ld_term, consignee ?? cur.consignee,
    consignee_address ?? cur.consignee_address, req.params.id
  );
  res.json(db.prepare("SELECT * FROM jobs WHERE id=?").get(req.params.id));
});

// Build and return the PEDI-format XML for a vessel/voyage
app.get("/api/edi/export/:vesselId/:voyageId", (req, res) => {
  const { vesselId, voyageId } = req.params;
  const vessel = db.prepare("SELECT * FROM vessels WHERE id=?").get(vesselId);
  const voyage = db.prepare("SELECT * FROM voyages WHERE id=?").get(voyageId);
  if (!vessel || !voyage) return res.status(404).json({ error: "Vessel/voyage not found" });
  const manifest = db.prepare("SELECT * FROM manifests WHERE vessel_id=? AND voyage_id=?").get(vesselId, voyageId) || {};
  const jobs = db.prepare("SELECT * FROM jobs WHERE vessel_id=? AND voyage_id=?").all(vesselId, voyageId);

  const today = new Date().toISOString().slice(0,10);
  const blsXml = jobs.map(j => {
    const bl = db.prepare("SELECT * FROM job_bl WHERE job_id=?").get(j.id) || {};
    const containers = db.prepare("SELECT * FROM job_containers WHERE job_id=?").all(j.id);
    const totalWeight = containers.reduce((s,c)=>s+Number(c.weight||0),0) || 0;
    const shipperParty = findPartyByName(j.shipper) || {};
    const polPort = findPortByName(j.pol);
    const podPort = findPortByName(j.pod);
    const finalPort = findPortByName(j.final_dest || j.pod);
    const containerXml = (containers.length ? containers : [{ size:"20SD", no:"", seal:"", weight:0 }]).map(c => `
                    <Container>
                        <ContainerType>${isoForSize(c.size)}</ContainerType>
                        <ContainerNo>${xmlEscape(c.no)}</ContainerNo>
                        <SealNo>${xmlEscape(c.seal)}</SealNo>
                        <APart />
                        <NW>0</NW>
                        <GW>${Number(c.weight||0).toFixed(3)}</GW>
                        <QTY>0</QTY>
                        <PackageUnit />
                        <CBM>0</CBM>
                    </Container>`).join("");
    return `
            <BL>
                <BLNo>${xmlEscape(bl.hbl || j.job_no)}</BLNo>
                <MBLNo>${xmlEscape(bl.mbl || bl.hbl || j.job_no)}</MBLNo>
                <BLDate>${ymd(j.job_date)}</BLDate>
                <GoodsLCNo />
                <FPNo />
                <Weight>${totalWeight.toFixed(3)}</Weight>
                <NetWeight>0</NetWeight>
                <Volume>0</Volume>
                <WeightUnit>MT</WeightUnit>
                <VolumeUnit>CBM</VolumeUnit>
                <Term>${xmlEscape(j.incoterm || "")}</Term>
                <LoadPort>${xmlEscape(polPort ? polPort.locode : j.pol)}</LoadPort>
                <DiscPort>${xmlEscape(podPort ? podPort.locode : j.pod)}</DiscPort>
                <Origin>${xmlEscape(polPort ? polPort.locode : j.pol)}</Origin>
                <FinalDest>${xmlEscape(finalPort ? finalPort.locode : (j.final_dest || j.pod))}</FinalDest>
                <LDTerm>${xmlEscape((j.ld_term||"").replace("/",""))}</LDTerm>
                <Payment>${j.freight_type === "Collect" ? "C" : "P"}</Payment>
                <Shipper>
                    <ShipperCode>${xmlEscape(shipperParty.edi_code || "")}</ShipperCode>
                    <ShipperName>${xmlEscape(j.shipper)}</ShipperName>
                    <ShipperAddress>${xmlEscape(shipperParty.address || "")}</ShipperAddress>
                    <ShipperTel />
                    <ShipperFax />
                </Shipper>
                <Consignee>${xmlEscape(j.consignee || "")}</Consignee>
                <NotifyAddress>${xmlEscape(j.consignee_address || "")}</NotifyAddress>
                <Marks />
                <Description />
                <Commodity>${xmlEscape(j.commodity || "")}</Commodity>
                <HSCode />
                <FreeData>
                    <POFDFreeDays />
                    <POLFreeDays />
                </FreeData>
                <ContainerData>${containerXml}
                </ContainerData>
                <PricingData />
            </BL>`;
  }).join("");

  const xml = `<?xml version="1.0" encoding="utf-8" ?>
<Data>
    <Manifest>
        <ManifestDate>${ymd(today)}</ManifestDate>
        <Reference>${xmlEscape(manifest.reference || "")}</Reference>
        <ProjectCode>${xmlEscape(manifest.project_code || "")}</ProjectCode>
        <SailingDate>${ymd(voyage.etd)}</SailingDate>
        <Vessel>${xmlEscape(vessel.name)}</Vessel>
        <Voyage>${xmlEscape(voyage.no)}</Voyage>
        <OverseasAgent>${xmlEscape(manifest.overseas_agent || "")}</OverseasAgent>
        <BLs>${blsXml}
        </BLs>
    </Manifest>
</Data>
`;
  res.setHeader("Content-Type", "application/xml");
  res.setHeader("Content-Disposition", `attachment; filename="PEDI_Exp-${vessel.name.replace(/\s+/g,"_")}-${voyage.no}.xml"`);
  res.send(xml);
});

// Import a PEDI-format XML: creates/updates vessel, voyage, jobs, BLs, containers, shipper parties
app.post("/api/edi/import", (req, res) => {
  const { xml } = req.body;
  if (!xml) return res.status(400).json({ error: "No XML content provided" });

  let parsed;
  try {
    const parser = new XMLParser({ ignoreAttributes: true, trimValues: false, parseTagValue: false });
    parsed = parser.parse(xml);
  } catch (e) {
    return res.status(400).json({ error: "Could not parse XML: " + e.message });
  }
  const manifestData = parsed?.Data?.Manifest;
  if (!manifestData) return res.status(400).json({ error: "This doesn't look like a PEDI manifest file (missing <Data><Manifest>)" });

  let bls = manifestData.BLs?.BL || [];
  if (!Array.isArray(bls)) bls = [bls];

  const vesselName = manifestData.Vessel || "";
  const voyageNo = manifestData.Voyage || "";
  const sailingDate = dashDate(manifestData.SailingDate);

  let vessel = db.prepare("SELECT * FROM vessels WHERE name = ? COLLATE NOCASE").get(vesselName);
  if (!vessel) {
    const info = db.prepare("INSERT INTO vessels (name) VALUES (?)").run(vesselName);
    vessel = { id: info.lastInsertRowid, name: vesselName };
  }
  let voyage = db.prepare("SELECT * FROM voyages WHERE vessel_id=? AND no=?").get(vessel.id, voyageNo);
  if (!voyage) {
    const info = db.prepare("INSERT INTO voyages (vessel_id, no, etd, eta) VALUES (?,?,?,?)")
      .run(vessel.id, voyageNo, sailingDate, sailingDate);
    voyage = { id: info.lastInsertRowid, vessel_id: vessel.id, no: voyageNo };
  }

  const existingManifest = db.prepare("SELECT id FROM manifests WHERE vessel_id=? AND voyage_id=?").get(vessel.id, voyage.id);
  if (existingManifest) {
    db.prepare("UPDATE manifests SET overseas_agent=?, reference=?, project_code=? WHERE id=?")
      .run(manifestData.OverseasAgent || "", manifestData.Reference || "", manifestData.ProjectCode || "", existingManifest.id);
  } else {
    db.prepare("INSERT INTO manifests (vessel_id, voyage_id, overseas_agent, reference, project_code) VALUES (?,?,?,?,?)")
      .run(vessel.id, voyage.id, manifestData.OverseasAgent || "", manifestData.Reference || "", manifestData.ProjectCode || "");
  }

  let created = 0, updated = 0;
  const errors = [];

  bls.forEach(bl => {
    try {
      const blNo = bl.BLNo || "";
      if (!blNo) { errors.push("A <BL> entry had no BLNo — skipped"); return; }

      // find/create shipper party
      const shipperObj = bl.Shipper || {};
      const shipperName = shipperObj.ShipperName || "";
      if (shipperName) {
        let party = db.prepare("SELECT * FROM parties WHERE name = ? COLLATE NOCASE").get(shipperName);
        const addr = typeof shipperObj.ShipperAddress === "string" ? shipperObj.ShipperAddress.trim() : "";
        if (!party) {
          db.prepare("INSERT INTO parties (name, type, code, contact, address, edi_code) VALUES (?,?,?,?,?,?)")
            .run(shipperName, "Customer", shipperObj.ShipperCode || "", "", addr, shipperObj.ShipperCode || "");
        } else if (!party.address || !party.edi_code) {
          db.prepare("UPDATE parties SET address=COALESCE(NULLIF(address,''),?), edi_code=COALESCE(NULLIF(edi_code,''),?) WHERE id=?")
            .run(addr, shipperObj.ShipperCode || "", party.id);
        }
      }

      let job = db.prepare("SELECT * FROM jobs WHERE job_no = ?").get(blNo);
      const payload = {
        job_date: dashDate(bl.BLDate) || sailingDate,
        vessel_id: vessel.id, voyage_id: voyage.id,
        client: shipperName, shipper: shipperName,
        consignee: typeof bl.Consignee === "string" ? bl.Consignee.trim() : "",
        consignee_address: typeof bl.NotifyAddress === "string" ? bl.NotifyAddress.trim() : "",
        commodity: bl.Commodity || "GENERAL CARGO",
        pol: portNameForLocode(bl.LoadPort) || bl.LoadPort || "",
        pod: portNameForLocode(bl.DiscPort) || bl.DiscPort || "",
        final_dest: portNameForLocode(bl.FinalDest) || bl.FinalDest || portNameForLocode(bl.DiscPort) || bl.DiscPort || "",
        incoterm: bl.Term || "", ld_term: bl.LDTerm || "",
        freight_type: bl.Payment === "C" ? "Collect" : "Prepaid",
      };

      if (job) {
        db.prepare(`UPDATE jobs SET job_date=?, vessel_id=?, voyage_id=?, client=?, shipper=?, consignee=?,
          consignee_address=?, commodity=?, pol=?, pod=?, final_dest=?, incoterm=?, ld_term=?, freight_type=? WHERE id=?`)
          .run(payload.job_date, payload.vessel_id, payload.voyage_id, payload.client, payload.shipper, payload.consignee,
               payload.consignee_address, payload.commodity, payload.pol, payload.pod, payload.final_dest,
               payload.incoterm, payload.ld_term, payload.freight_type, job.id);
        updated++;
      } else {
        const info = db.prepare(`INSERT INTO jobs (job_no, job_date, vessel_id, voyage_id, client, shipper, consignee,
          consignee_address, commodity, pol, pod, final_dest, incoterm, ld_term, freight_type)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
          .run(blNo, payload.job_date, payload.vessel_id, payload.voyage_id, payload.client, payload.shipper, payload.consignee,
               payload.consignee_address, payload.commodity, payload.pol, payload.pod, payload.final_dest,
               payload.incoterm, payload.ld_term, payload.freight_type);
        job = { id: info.lastInsertRowid };
        created++;
      }

      // BL header
      const blExists = db.prepare("SELECT job_id FROM job_bl WHERE job_id=?").get(job.id);
      if (blExists) {
        db.prepare("UPDATE job_bl SET hbl=?, mbl=? WHERE job_id=?").run(blNo, bl.MBLNo || blNo, job.id);
      } else {
        db.prepare("INSERT INTO job_bl (job_id, hbl, mbl, release_status, handover_type) VALUES (?,?,?,?,?)")
          .run(job.id, blNo, bl.MBLNo || blNo, "Original", "By Hand");
      }

      // containers: replace existing set for this job with what's in the file
      let containerData = bl.ContainerData?.Container || [];
      if (!Array.isArray(containerData)) containerData = [containerData];
      db.prepare("DELETE FROM job_containers WHERE job_id=?").run(job.id);
      const insCont = db.prepare("INSERT INTO job_containers (job_id, no, seal, size, weight) VALUES (?,?,?,?,?)");
      containerData.forEach(c => {
        insCont.run(job.id, c.ContainerNo || "", c.SealNo || "", sizeForIso(c.ContainerType), Number(c.GW || 0));
      });
      db.prepare("DELETE FROM job_equipment WHERE job_id=?").run(job.id);
      const insEq = db.prepare("INSERT INTO job_equipment (job_id, size, qty, dg) VALUES (?,?,?,?)");
      const sizeCounts = {};
      containerData.forEach(c => { const sz = sizeForIso(c.ContainerType); sizeCounts[sz] = (sizeCounts[sz]||0)+1; });
      Object.entries(sizeCounts).forEach(([sz,qty]) => insEq.run(job.id, sz, qty, "Non DG"));

    } catch (e) {
      errors.push(`BL ${bl.BLNo || "?"}: ${e.message}`);
    }
  });

  res.json({ vessel: vessel.name, voyage: voyage.no, created, updated, errors });
});

/* ---------------------------------------------------------------- */
const PORT = process.env.PORT || 3000;
setInterval(runScheduledCampaigns, 60 * 1000); // vessel-schedule marketing email scheduler, checked every minute
app.listen(PORT, () => console.log(`Harbor Desk ERP running on http://localhost:${PORT}`));
