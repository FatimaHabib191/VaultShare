// Runs before start/seed/test/evaluate (npm "pre" scripts). Imports nothing, so it
// works on any Node version and explains the problem instead of a cryptic crash.
const [major, minor] = process.versions.node.split('.').map(Number);
if (major < 22 || (major === 22 && minor < 13)) {
  console.error(`\n  VaultShare needs Node.js 22.13 or newer (it uses the built-in node:sqlite).`);
  console.error(`  You have Node.js ${process.versions.node}. Install the current LTS from https://nodejs.org and try again.\n`);
  process.exit(1);
}
