// Diagnostic startup wrapper — set this as the cPanel "Application startup file" (instead of
// server.js) if the app shows a generic Phusion Passenger 500 error with no visible cause.
// It catches any crash during startup and writes the real error/stack trace to
// startup-error.log in this folder, readable via File Manager, even without Terminal/SSH access.
const fs = require("fs");
const path = require("path");
const logPath = path.join(__dirname, "startup-error.log");
function logAndExit(err) {
  const entry = `\n----- ${new Date().toISOString()} -----\n${err && err.stack ? err.stack : String(err)}\n`;
  try { fs.appendFileSync(logPath, entry); } catch (e) {}
  console.error(entry);
  process.exit(1);
}
process.on("uncaughtException", logAndExit);
process.on("unhandledRejection", logAndExit);
try { require("./server.js"); } catch (err) { logAndExit(err); }
