'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { HiveManager } = loadTs('src/main/hive.ts');

async function createWatchdogsFloor(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'watchdogs-hive-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const hive = new HiveManager(() => home);

  // Setup Michael (Manager), Jonathan (HackerGPT), and Daniel (Shannon)
  await hive.ensureAgent({ id: 'michael', name: 'Michael', provider: 'claude', cwd: home, isGod: true });
  await hive.ensureAgent({ id: 'jonathan', name: 'Jonathan', provider: 'hackergpt', cwd: home });
  await hive.ensureAgent({ id: 'daniel', name: 'Daniel', provider: 'shannon', cwd: home });

  return { home, hive };
}

test('Phase 2.3: Hand-crafted test message placed in outbox arrives in recipient inbox with schema intact', async (t) => {
  const { home, hive } = await createWatchdogsFloor(t);

  const jonathanOutbox = path.join(home, 'hive', 'agents', 'jonathan', 'outbox');
  const danielInbox = path.join(home, 'hive', 'agents', 'daniel', 'inbox');

  const testMessage = {
    id: 'test-finding-001',
    conversation: 'conv-test-1',
    in_reply_to: null,
    to: 'daniel',
    act: 'inform',
    subject: 'Target recon data',
    body: 'Ports and services discovered',
    finding: {
      target: 'authorized.lab',
      phase: 'recon',
      finding_type: 'open_port',
      severity: 'info',
      evidence: '80/tcp open http\n443/tcp open https',
      source_desk: '/jonathan',
      requires_approval: false
    }
  };

  // Write hand-crafted message into Jonathan's outbox
  const outboxFilePath = path.join(jonathanOutbox, 'msg-001.json');
  fs.writeFileSync(outboxFilePath, JSON.stringify(testMessage), 'utf8');

  // Verify it exists in outbox before routing
  assert.equal(fs.existsSync(outboxFilePath), true);

  // Trigger one route pass
  const routedCount = hive.routeOnce();
  assert.equal(routedCount, 1, 'Exactly one message should be routed');

  // Verify message has been drained from Jonathan's outbox and archived in .sent
  assert.equal(fs.existsSync(outboxFilePath), false, 'Message should no longer be in outbox');
  assert.equal(fs.existsSync(path.join(jonathanOutbox, '.sent', 'msg-001.json')), true, 'Message should be archived in outbox/.sent');

  // Verify message arrived in Daniel's inbox
  const deliveredMessages = hive.inbox('daniel');
  assert.equal(deliveredMessages.length, 1, 'Daniel should have received the message');

  const received = deliveredMessages[0];
  assert.equal(received.from, 'jonathan');
  assert.equal(received.to, 'daniel');
  assert.equal(received.subject, 'Target recon data');
  assert.deepEqual(received.finding, testMessage.finding, 'The Watchdogs finding payload must arrive intact');
});
