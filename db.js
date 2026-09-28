const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");

const db = new Database(path.join(__dirname, "harbor-desk.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS vessels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS voyages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vessel_id INTEGER NOT NULL REFERENCES vessels(id) ON DELETE CASCADE,
  no TEXT NOT NULL,
  etd TEXT,
  eta TEXT
);

CREATE TABLE IF NOT EXISTS parties (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('Customer','Vendor')),
  code TEXT,
  contact TEXT
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  username TEXT UNIQUE NOT NULL,
  role TEXT NOT NULL,
  modules TEXT NOT NULL,      -- comma separated: job,accounting,admin,reports
  active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_no TEXT UNIQUE NOT NULL,
  job_date TEXT,
  job_type TEXT DEFAULT 'Direct',
  cost_center TEXT DEFAULT 'HEAD OFFICE',
  freight_type TEXT DEFAULT 'Prepaid',
  sales_rep TEXT,
  client TEXT, shipper TEXT, consignee TEXT,
  commodity TEXT DEFAULT 'GENERAL CARGO',
  pol TEXT, pod TEXT, final_dest TEXT,
  vessel_id INTEGER REFERENCES vessels(id),
  voyage_id INTEGER REFERENCES voyages(id),
  etd TEXT, eta TEXT,
  booking_approved INTEGER DEFAULT 0,
  charges_approved INTEGER DEFAULT 0,
  job_approved INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS job_equipment (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  size TEXT NOT NULL,
  qty INTEGER NOT NULL DEFAULT 0,
  dg TEXT DEFAULT 'Non DG'
);

CREATE TABLE IF NOT EXISTS job_charges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  code TEXT NOT NULL,
  size TEXT NOT NULL,
  rate REAL NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT 'USD'
);

CREATE TABLE IF NOT EXISTS job_bl (
  job_id INTEGER PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
  hbl TEXT, mbl TEXT,
  release_status TEXT DEFAULT 'Original',
  handover_type TEXT DEFAULT 'By Hand'
);

CREATE TABLE IF NOT EXISTS job_containers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  no TEXT, seal TEXT, size TEXT, weight REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS invoices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  txn TEXT UNIQUE,
  date TEXT,
  currency TEXT DEFAULT 'USD',
  bank TEXT,
  amount REAL DEFAULT 0,
  settled INTEGER DEFAULT 0,
  settled_amount REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ap_bills (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bill_no TEXT,
  vendor TEXT,
  job_id INTEGER REFERENCES jobs(id),
  date TEXT,
  amount REAL DEFAULT 0,
  settled INTEGER DEFAULT 0,
  settled_amount REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS accounts (
  code TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('Asset','Liability','Equity','Income','Expense'))
);

CREATE TABLE IF NOT EXISTS vouchers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  no TEXT,
  date TEXT,
  narration TEXT,
  source TEXT
);

CREATE TABLE IF NOT EXISTS voucher_lines (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  voucher_id INTEGER NOT NULL REFERENCES vouchers(id) ON DELETE CASCADE,
  account_code TEXT NOT NULL REFERENCES accounts(code),
  debit REAL DEFAULT 0,
  credit REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS manifests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vessel_id INTEGER NOT NULL REFERENCES vessels(id),
  voyage_id INTEGER NOT NULL REFERENCES voyages(id),
  overseas_agent TEXT,
  reference TEXT,
  project_code TEXT,
  UNIQUE(vessel_id, voyage_id)
);

CREATE TABLE IF NOT EXISTS job_sequences (
  year TEXT PRIMARY KEY,
  last_no INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS commodities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS charge_codes (
  code TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  account_code TEXT REFERENCES accounts(code)
);

CREATE TABLE IF NOT EXISTS ports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  country TEXT,
  locode TEXT
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS activity_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT DEFAULT (datetime('now')),
  user_id INTEGER,
  username TEXT,
  action TEXT,
  details TEXT
);

CREATE TABLE IF NOT EXISTS email_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT DEFAULT (datetime('now')),
  sent_by_user_id INTEGER,
  sent_by_username TEXT,
  to_email TEXT,
  subject TEXT,
  related_type TEXT,
  related_ref TEXT,
  status TEXT,
  error TEXT
);

CREATE TABLE IF NOT EXISTS ap_bill_jobs (
  bill_id INTEGER NOT NULL REFERENCES ap_bills(id) ON DELETE CASCADE,
  job_id INTEGER NOT NULL REFERENCES jobs(id),
  PRIMARY KEY (bill_id, job_id)
);

CREATE TABLE IF NOT EXISTS vessel_campaigns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vessel_id INTEGER REFERENCES vessels(id),
  voyage_id INTEGER REFERENCES voyages(id),
  vessel_name TEXT, voyage_no TEXT,
  pol TEXT, pod TEXT, etd TEXT, eta TEXT,
  subject TEXT, message TEXT,
  to_list TEXT, cc_list TEXT, bcc_list TEXT,
  recipient_count INTEGER DEFAULT 0,
  schedule_start_date TEXT,
  send_times TEXT DEFAULT '[]',
  is_running INTEGER DEFAULT 0,
  started_by_user_id INTEGER,
  started_by_username TEXT,
  started_at TEXT,
  last_sent_date TEXT,
  last_sent_times TEXT DEFAULT '[]',
  base_url TEXT,
  created_by_username TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
`);

ensureColumn("vessels", "vendor_party_id", "vendor_party_id INTEGER REFERENCES parties(id)");
ensureColumn("vessels", "code", "code TEXT");
ensureColumn("voyages", "closed", "closed INTEGER DEFAULT 0");
ensureColumn("voyages", "cut_off", "cut_off TEXT");
ensureColumn("jobs", "cut_off", "cut_off TEXT");
ensureColumn("ap_bills", "vessel_id", "vessel_id INTEGER REFERENCES vessels(id)");
ensureColumn("ap_bills", "voyage_id", "voyage_id INTEGER REFERENCES voyages(id)");
ensureColumn("ap_bills", "against_type", "against_type TEXT DEFAULT 'Service'");
ensureColumn("ap_bills", "against_ref", "against_ref TEXT");
ensureColumn("jobs", "direction", "direction TEXT DEFAULT 'Export'");
ensureColumn("users", "can_export", "can_export INTEGER DEFAULT 1");
ensureColumn("users", "can_import", "can_import INTEGER DEFAULT 0");

// ---- idempotent migrations: add EDI-related columns if they don't already exist ----
function ensureColumn(table, column, ddl) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
  if (!cols.includes(column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
  }
}
ensureColumn("jobs", "incoterm", "incoterm TEXT DEFAULT 'CFR'");
ensureColumn("jobs", "ld_term", "ld_term TEXT DEFAULT 'CY/CY'");
ensureColumn("jobs", "consignee_address", "consignee_address TEXT");
ensureColumn("parties", "address", "address TEXT");
ensureColumn("parties", "edi_code", "edi_code TEXT");
ensureColumn("parties", "email", "email TEXT");
ensureColumn("invoices", "vat_rate", "vat_rate REAL DEFAULT 0");
ensureColumn("invoices", "vat_amount", "vat_amount REAL DEFAULT 0");
ensureColumn("invoices", "vat_account", "vat_account TEXT");
ensureColumn("invoices", "exchange_rate", "exchange_rate REAL DEFAULT 1");
ensureColumn("users", "password_hash", "password_hash TEXT DEFAULT ''");
ensureColumn("users", "can_delete", "can_delete INTEGER DEFAULT 0");
ensureColumn("parties", "is_client", "is_client INTEGER DEFAULT 0");
ensureColumn("parties", "is_shipper", "is_shipper INTEGER DEFAULT 0");
ensureColumn("parties", "is_consignee", "is_consignee INTEGER DEFAULT 0");
ensureColumn("parties", "is_vendor", "is_vendor INTEGER DEFAULT 0");
ensureColumn("users", "chatbot_only", "chatbot_only INTEGER DEFAULT 0"); // when set, this user can ONLY open the chatbot page
ensureColumn("vessel_campaigns", "pol_list", "pol_list TEXT DEFAULT '[]'"); // JSON [{port, eta}, ...] — multiple loading ports, each with its own ETA
ensureColumn("vessel_campaigns", "pod_list", "pod_list TEXT DEFAULT '[]'"); // JSON [{port, eta}, ...] — multiple discharge ports, each with its own ETA

// ---- Agent linked to a party (used by client receipts) ----
ensureColumn("parties", "agent_name", "agent_name TEXT");

// ---- Chart of Accounts: groups + client/charge linkage ----
db.exec(`
CREATE TABLE IF NOT EXISTS account_groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('Asset','Liability','Equity','Income','Expense')),
  prefix TEXT NOT NULL,   -- e.g. '10' -> auto-generated codes 1001,1002,...
  UNIQUE(prefix)
);
`);
ensureColumn("accounts", "group_id", "group_id INTEGER REFERENCES account_groups(id)");
ensureColumn("accounts", "linked_party_id", "linked_party_id INTEGER REFERENCES parties(id)");
ensureColumn("accounts", "linked_charge_code", "linked_charge_code TEXT REFERENCES charge_codes(code)");

const groupCount = db.prepare("SELECT COUNT(*) c FROM account_groups").get().c;
if (groupCount === 0) {
  const insG = db.prepare("INSERT INTO account_groups (name, type, prefix) VALUES (?,?,?)");
  const seedG = db.transaction((rows) => rows.forEach(r => insG.run(...r)));
  seedG([
    ["Accounts Receivable", "Asset", "10"],
    ["Cash & Bank", "Asset", "11"],
    ["Accounts Payable", "Liability", "20"],
    ["Other Liabilities", "Liability", "21"],
    ["Owner's Equity", "Equity", "30"],
    ["Freight & Slot Revenue", "Income", "40"],
    ["Other Revenue", "Income", "41"],
    ["Direct Cost", "Expense", "50"],
    ["Operating Expense", "Expense", "51"],
  ]);
}

// One-time migration: any existing Admin user should have chatbot access by default too.
db.prepare("SELECT id, modules FROM users WHERE role='Admin'").all().forEach(u => {
  const mods = (u.modules || "").split(",").filter(Boolean);
  if (!mods.includes("chatbot")) {
    mods.push("chatbot");
    db.prepare("UPDATE users SET modules=? WHERE id=?").run(mods.join(","), u.id);
  }
});
ensureColumn("voucher_lines", "reconciled", "reconciled INTEGER DEFAULT 0");
ensureColumn("voucher_lines", "reconciled_date", "reconciled_date TEXT");

// ---- Job Costs: DRAFT cost/payable line items (mirrors job_charges) — these are just data entry
// until "Generate Bill" bundles a vendor's draft lines into an actual ap_bills row + GL posting,
// exactly the way job_charges lines stay drafts until "Generate Invoice" posts them.
db.exec(`
CREATE TABLE IF NOT EXISTS job_costs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  vendor TEXT NOT NULL,
  description TEXT,
  size TEXT,
  qty REAL,
  rate REAL,
  amount REAL DEFAULT 0,
  currency TEXT DEFAULT 'AED',
  exchange_rate REAL DEFAULT 1,
  expense_account TEXT,
  bill_type TEXT DEFAULT 'Regular',
  bill_id INTEGER REFERENCES ap_bills(id),
  created_at TEXT DEFAULT (datetime('now'))
);
`);

// ---- Approve/Edit rights for Charges & Cost — a distinct permission from can_delete/export/import ----
ensureColumn("users", "can_approve", "can_approve INTEGER DEFAULT 0");
// Existing Admins get approve rights by default too (new installs already get this via the INSERT above).
db.prepare("UPDATE users SET can_approve=1 WHERE role='Admin' AND can_approve=0").run();

// ---- Account lockout after repeated failed logins ----
ensureColumn("users", "failed_attempts", "failed_attempts INTEGER DEFAULT 0");
ensureColumn("users", "locked", "locked INTEGER DEFAULT 0");

// ---- Voyage rotation number (unique) ----
ensureColumn("voyages", "rotation_no", "rotation_no TEXT");

// ---- B/L Detail fields (from the legacy B/L screen) — POL/POD/Vessel/Voyage/Freight Type already
// come from Booking automatically, so only the fields that DON'T exist there get their own inputs.
ensureColumn("job_bl", "place_of_receipt", "place_of_receipt TEXT");
ensureColumn("job_bl", "place_of_delivery", "place_of_delivery TEXT");
ensureColumn("job_bl", "weight_unit", "weight_unit TEXT DEFAULT 'KGS'");
ensureColumn("job_bl", "hide_freight_type", "hide_freight_type INTEGER DEFAULT 0");
ensureColumn("job_bl", "delivery_agent", "delivery_agent TEXT");
ensureColumn("job_bl", "no_of_originals", "no_of_originals TEXT");
ensureColumn("job_bl", "agent_stamp", "agent_stamp TEXT");
ensureColumn("job_bl", "marks_and_numbers", "marks_and_numbers TEXT");
ensureColumn("job_bl", "no_of_packages", "no_of_packages TEXT");
ensureColumn("job_bl", "goods_description", "goods_description TEXT");
ensureColumn("job_containers", "net_weight", "net_weight REAL DEFAULT 0");
ensureColumn("job_containers", "measurement", "measurement REAL DEFAULT 0"); // CBM

// ---- Manual quantity override for revenue charge lines (still defaults from Equipment) ----
ensureColumn("job_charges", "qty_override", "qty_override INTEGER");

// ---- Payable/Cost: optional qty/rate/size, same pattern as revenue Charges ----
ensureColumn("ap_bills", "size", "size TEXT");
ensureColumn("ap_bills", "qty", "qty REAL");
ensureColumn("ap_bills", "rate", "rate REAL");
ensureColumn("ap_bills", "bill_type", "bill_type TEXT DEFAULT 'Regular'"); // 'Regular' | 'Advance'

// ---- Credit Notes (reduce a client's receivable) & Debit Notes (adjust a vendor's payable) ----
db.exec(`
CREATE TABLE IF NOT EXISTS credit_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cn_no TEXT UNIQUE,
  client TEXT NOT NULL,
  invoice_id INTEGER REFERENCES invoices(id),
  date TEXT,
  amount REAL DEFAULT 0,
  reason TEXT,
  account_code TEXT
);
CREATE TABLE IF NOT EXISTS debit_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  dn_no TEXT UNIQUE,
  vendor TEXT NOT NULL,
  bill_id INTEGER REFERENCES ap_bills(id),
  date TEXT,
  amount REAL DEFAULT 0,
  reason TEXT,
  account_code TEXT
);
`);

// ---- Customer TRN / Trade License — must be unique across parties ----
ensureColumn("parties", "trn", "trn TEXT");
ensureColumn("parties", "trade_license", "trade_license TEXT");

// ---- Payment mode (Cash / Online / Cheque) on receipts & payments ----
ensureColumn("vouchers", "payment_mode", "payment_mode TEXT"); // 'Cash' | 'Online' | 'Cheque'
ensureColumn("vouchers", "reference_no", "reference_no TEXT"); // transaction # (Online) or cheque # (Cheque)

// ---- Vendor bill currency (locked once posted — see server-side edit guard) ----
ensureColumn("ap_bills", "currency", "currency TEXT DEFAULT 'AED'");
ensureColumn("ap_bills", "exchange_rate", "exchange_rate REAL DEFAULT 1");
ensureColumn("ap_bills", "base_amount", "base_amount REAL DEFAULT 0"); // amount converted to AED, used for GL posting

// ---- Charges: cost/payable lines tied to a vendor, recorded right alongside revenue charges ----
ensureColumn("job_charges", "kind", "kind TEXT DEFAULT 'revenue'"); // 'revenue' | 'cost'
ensureColumn("job_charges", "vendor", "vendor TEXT");
ensureColumn("job_charges", "exchange_rate", "exchange_rate REAL DEFAULT 1"); // same AED-conversion pattern as ap_bills

// backfill role flags from the old single "type" field, once
db.prepare("UPDATE parties SET is_client=1 WHERE type='Customer' AND is_client=0 AND is_shipper=0 AND is_consignee=0 AND is_vendor=0").run();
db.prepare("UPDATE parties SET is_vendor=1 WHERE type='Vendor' AND is_client=0 AND is_shipper=0 AND is_consignee=0 AND is_vendor=0").run();

// ---- seed default accounts (only if empty) ----
const acctCount = db.prepare("SELECT COUNT(*) c FROM accounts").get().c;
if (acctCount === 0) {
  const insert = db.prepare("INSERT INTO accounts (code,name,type) VALUES (?,?,?)");
  const seed = db.transaction((rows) => rows.forEach(r => insert.run(...r)));
  seed([
    ["1000", "Accounts Receivable — Trade", "Asset"],
    ["1010", "Cash & Bank — FAB AED", "Asset"],
    ["1020", "Cash & Bank — ENBD USD", "Asset"],
    ["2000", "Accounts Payable — Vendors", "Liability"],
    ["3000", "Owner's Equity", "Equity"],
    ["4000", "Freight & Slot Revenue", "Income"],
    ["4010", "THC & Handling Revenue", "Income"],
    ["4020", "Storage Revenue", "Income"],
    ["5000", "Ocean Freight Cost", "Expense"],
    ["5010", "Terminal / THC Cost", "Expense"],
    ["5020", "Operating Expenses", "Expense"],
    ["5030", "Bank Charges", "Expense"],
    ["2100", "VAT Payable", "Liability"]
  ]);
}

// ---- seed worldwide ports master from db/ports-seed.json (only if empty) ----
const portCount = db.prepare("SELECT COUNT(*) c FROM ports").get().c;
if (portCount === 0) {
  const portsSeedPath = path.join(__dirname, "db", "ports-seed.json");
  if (fs.existsSync(portsSeedPath)) {
    const portsData = JSON.parse(fs.readFileSync(portsSeedPath, "utf8"));
    const insP = db.prepare("INSERT INTO ports (name, country, locode) VALUES (?,?,?)");
    const seedP = db.transaction((rows) => rows.forEach(r => insP.run(r.name, r.country || "", r.locode || "")));
    seedP(portsData);
  }
}

// safety net: ensure VAT Payable account exists even on DBs seeded before this feature
if (!db.prepare("SELECT code FROM accounts WHERE code='2100'").get()) {
  db.prepare("INSERT INTO accounts (code, name, type) VALUES ('2100','VAT Payable','Liability')").run();
}

// ---- seed default charge codes (only if empty) — must run after accounts exist ----
const chargeCodeCount = db.prepare("SELECT COUNT(*) c FROM charge_codes").get().c;
if (chargeCodeCount === 0) {
  const insCC = db.prepare("INSERT INTO charge_codes (code, name, account_code) VALUES (?,?,?)");
  const seedCC = db.transaction((rows) => rows.forEach(r => insCC.run(...r)));
  seedCC([
    ["SLOT", "Slot Charges", "4000"],
    ["THC", "Terminal Handling Charges", "4010"],
    ["111", "Transhipment THC", "4010"],
    ["STOR", "Storage", "4020"],
    ["DOC", "Documentation Fee", "4000"],
    ["SEAL", "Seal Charges", "4000"],
  ]);
}

// ---- seed default admin user ----
const bcrypt = require("bcryptjs");
const userCount = db.prepare("SELECT COUNT(*) c FROM users").get().c;
if (userCount === 0) {
  const hash = bcrypt.hashSync("admin123", 10);
  db.prepare("INSERT INTO users (name, username, role, modules, active, password_hash, can_delete, can_export, can_import, can_approve) VALUES (?,?,?,?,1,?,1,1,1,1)")
    .run("System Admin", "admin", "Admin", "job,accounting,admin,reports,chatbot", hash);
} else {
  // backfill: any user created before passwords existed gets a default password so they can still log in
  const noPassword = db.prepare("SELECT id, username FROM users WHERE password_hash = '' OR password_hash IS NULL").all();
  if (noPassword.length) {
    const hash = bcrypt.hashSync("changeme123", 10);
    const upd = db.prepare("UPDATE users SET password_hash=? WHERE id=?");
    noPassword.forEach(u => upd.run(hash, u.id));
  }
  // Admin role always has delete rights, even on accounts created before this feature existed
  db.prepare("UPDATE users SET can_delete=1 WHERE role='Admin' AND can_delete=0").run();
  db.prepare("UPDATE users SET can_export=1, can_import=1 WHERE role='Admin'").run();
}

// ---- Booking "saved at least once" flag — Charges/Cost lines only need Booking to have been
// SAVED (not necessarily Approved) before they can be added; Approved locks the booking form
// itself from further edits until Un-approved. These are two separate gates on purpose.
ensureColumn("jobs", "booking_saved", "booking_saved INTEGER DEFAULT 0");

// ---- Charge Reference on Payable/Cost lines: which of the job's Charges a vendor bill is "against" ----
ensureColumn("job_costs", "charge_id", "charge_id INTEGER REFERENCES job_charges(id)");
ensureColumn("job_costs", "charge_ref", "charge_ref TEXT"); // human-readable snapshot (code/size/amount) so it still shows even if the charge line is later deleted
ensureColumn("ap_bills", "charge_ref", "charge_ref TEXT");  // carried onto the generated bill from its draft cost line(s)

// ---- Currency & Exchange Rate master table ----
db.exec(`
CREATE TABLE IF NOT EXISTS currencies (
  code TEXT PRIMARY KEY,
  name TEXT,
  exchange_rate REAL NOT NULL DEFAULT 1,
  applicable_from TEXT,
  notes TEXT,
  updated_at TEXT DEFAULT (datetime('now'))
);
`);
const currencyCount = db.prepare("SELECT COUNT(*) c FROM currencies").get().c;
if (currencyCount === 0) {
  const insCur = db.prepare("INSERT INTO currencies (code, name, exchange_rate, applicable_from, notes) VALUES (?,?,?,?,?)");
  const seedCur = db.transaction((rows) => rows.forEach(r => insCur.run(...r)));
  const today = new Date().toISOString().slice(0, 10);
  seedCur([
    ["AED", "UAE Dirham", 1, today, "Base currency — always 1"],
    ["USD", "US Dollar", 3.6, today, "Default AED conversion"],
  ]);
}

// ---- Sequencing gate: Booking must be saved & approved before Charges/Cost lines can be added,
// and Charges must be approved before any vendor bill can be generated from Cost lines. Enforced
// server-side in server.js — this migration just documents the columns those checks read.

// ---- default financial year setting (2-digit year), only if not already set ----
const fyExists = db.prepare("SELECT value FROM settings WHERE key='financial_year'").get();
if (!fyExists) {
  db.prepare("INSERT INTO settings (key, value) VALUES ('financial_year', ?)")
    .run(new Date().getFullYear().toString().slice(-2));
}

// ---- backfill: give every existing vessel a serial code (V-0001, V-0002, ...) if it doesn't have one ----
(function backfillVesselCodes() {
  const missing = db.prepare("SELECT id FROM vessels WHERE code IS NULL OR code=''").all();
  if (!missing.length) return;
  let n = db.prepare("SELECT COUNT(*) c FROM vessels WHERE code IS NOT NULL AND code!=''").get().c;
  const upd = db.prepare("UPDATE vessels SET code=? WHERE id=?");
  missing.forEach(v => { n++; upd.run(`V-${String(n).padStart(4, "0")}`, v.id); });
})();

// ---- Tariff master: pre-fixed rate cards per container size/type, one series each for Export
// (TRFE-0000/26) and Import (TRFI-0000/26). A Tariff has two kinds of lines:
//   tariff_charges — a revenue rate (charge code + size + rate), optionally scoped to one client;
//                    a NULL client_id means "applies to every client".
//   tariff_costs   — a cost rate (description + size + rate) scoped to exactly one vendor — a cost
//                    rate only makes sense for the vendor whose price it actually is.
// Like Booking, a Tariff is locked once Approved — edit is blocked until it's Un-approved again —
// and only an Approved tariff's lines are ever suggested/auto-filled into a job's Charges/Cost lines.
db.exec(`
CREATE TABLE IF NOT EXISTS tariffs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE NOT NULL,
  type TEXT NOT NULL, -- 'Export' | 'Import'
  name TEXT,
  effective_date TEXT,
  approved INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS tariff_charges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tariff_id INTEGER NOT NULL REFERENCES tariffs(id) ON DELETE CASCADE,
  code TEXT NOT NULL,
  size TEXT NOT NULL,
  rate REAL NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT 'AED',
  client_id INTEGER REFERENCES parties(id) -- NULL = applies to all clients
);
CREATE TABLE IF NOT EXISTS tariff_costs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tariff_id INTEGER NOT NULL REFERENCES tariffs(id) ON DELETE CASCADE,
  description TEXT NOT NULL,
  size TEXT NOT NULL,
  rate REAL NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT 'AED',
  vendor_id INTEGER NOT NULL REFERENCES parties(id)
);
`);

// ---- Tariff → Booking link: which job_charges/job_costs row was created by the "Apply Tariff"
// button (vs. added manually), so "Remove Tariff" can find and undo exactly those rows and only those.
ensureColumn("job_charges", "tariff_charge_id", "tariff_charge_id INTEGER REFERENCES tariff_charges(id)");
ensureColumn("job_costs", "tariff_cost_id", "tariff_cost_id INTEGER REFERENCES tariff_costs(id)");

module.exports = db;
