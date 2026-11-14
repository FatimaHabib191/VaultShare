import { createApp } from './app.js';

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1'; // local only by default

const { app, svc, close } = createApp({ dataDir: process.env.VS_DATA_DIR || undefined, secureCookies: process.env.VS_SECURE_COOKIES === '1' });

if (svc.repos.users.count() === 0) {
  console.log('\n  No users yet. Run "npm run seed" to create the demo accounts.\n');
}

const server = app.listen(PORT, HOST, () => {
  console.log(`  VaultShare running at http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n  Port ${PORT} is already in use. VaultShare may already be running in another terminal.`);
    console.error(`  Close that terminal, or start on another port:  PORT=3001 npm start  (Windows PowerShell: $env:PORT=3001; npm start)\n`);
  } else {
    console.error('\n  The server could not start:', err.message, '\n');
  }
  close();
  process.exit(1);
});

function shutdown() {
  server.close(() => {
    close();
    process.exit(0);
  });
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
