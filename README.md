# Harbor Desk ERP — Sea Export, Accounting, Admin & Reports

A real full-stack ERP: **Node.js + Express backend, SQLite database, separate HTML page per form.**
Every module you asked for is here as its own file, all backed by one shared database (`harbor-desk.db`), not browser memory — so data survives restarts, and multiple people on the network can use it at once.

## What's inside

```
harbor-desk-erp/
  server.js          -> Express server + all REST API routes
  db.js               -> SQLite schema + seed data (accounts, admin user)
  package.json
  public/
    job/booking.html        Booking Info (+ New Job / Save / Approve / Job List)
    job/equipment.html      Equipment
    job/charges.html        Charges
    job/bl.html              B/L & Containers (+ bulk paste)
    job/invoice.html        Invoice (generates + prints)
    job/joblist.html        All jobs created, with status & invoice
    accounting/coa.html          Chart of Accounts
    accounting/vouchers.html     Journal Vouchers
    accounting/ledger.html       Per-account Ledger
    accounting/receivables.html  Customer invoices + receipts
    accounting/payables.html     Vendor bills + payments
    accounting/trialbalance.html Trial Balance
    admin/vessels.html      Vessel & Voyage master
    admin/parties.html      Customers & Vendors master
    admin/users.html        Users & module access
    reports/index.html      All 19 reports (10 live, 9 standard templates)
```

Each form is its own HTML file that talks to the backend over a small REST API (`/api/...`) — nothing is held only in browser memory anymore. Refreshing, closing the tab, or restarting the server does not lose data; it's all in `harbor-desk.db`.

## Running it locally

You need [Node.js](https://nodejs.org) 18+ installed.

```bash
cd harbor-desk-erp
npm install
npm start
```

Then open **http://localhost:3000** in your browser. That's it — the database file `harbor-desk.db` is created automatically on first run in the same folder.

## About "live on your server"

I can't push this onto your own server myself — I don't have access to your hosting account, domain, or credentials, and this sandbox has no way to reach the public internet except package registries. You (or whoever manages your infrastructure) needs to do the actual deployment. Here are your realistic options, easiest first:

**Option A — a VPS you already have (DigitalOcean, AWS EC2, a shared Linux box, etc.)**
1. Upload this folder (e.g. `scp -r harbor-desk-erp user@yourserver:/var/www/`)
2. SSH in, run `cd /var/www/harbor-desk-erp && npm install`
3. Keep it running permanently with a process manager:
   ```bash
   npm install -g pm2
   pm2 start server.js --name harbor-desk
   pm2 save && pm2 startup
   ```
4. Put Nginx in front of it as a reverse proxy to port 3000, and point your domain at it. I can write the Nginx config if you tell me your domain.

**Option B — a platform that hosts Node apps for you (no server management)**
Services like Railway, Render, or Fly.io let you connect a GitHub repo and they build/run it for you, free tier available for light use. Push this folder to a GitHub repo, connect it there, and it deploys itself. I can walk you through whichever one you pick.

**Option C — ask Claude Code to do the deployment for you**
If you have (or can get) SSH access or an account on one of the above platforms, Claude Code (Anthropic's coding agent, run from your own machine/terminal) *can* actually SSH in and deploy this for you, because it runs on your machine with your credentials — this sandbox cannot.

## One more honest note on the database

SQLite (used here) is genuinely fine for one office / small team. If you expect many concurrent users or need remote database backups/replication, the same `db.js`/`server.js` structure can be pointed at PostgreSQL or MySQL instead with fairly small changes — happy to do that swap if you tell me which one your host supports.
