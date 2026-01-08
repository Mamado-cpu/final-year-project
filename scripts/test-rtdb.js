
// Small test to verify Firebase Admin SDK + Realtime Database connectivity
const { initializeFirebase, getRealtimeDb } = require('../src/config/firebase');

async function runTest() {
  try {
    initializeFirebase();
    const db = getRealtimeDb();
    const ref = db.ref('test_connection/node_backend');

    const payload = { ok: true, ts: Date.now() };
    console.log('Writing test payload to Realtime DB:', payload);
    await ref.set(payload);

    const snap = await ref.once('value');
    console.log('Read back value:', snap.val());
    console.log('Realtime DB test succeeded');
    process.exit(0);
  } catch (err) {
    console.error('Realtime DB test failed:', err && err.message ? err.message : err);
    process.exit(2);
  }
}

runTest();
