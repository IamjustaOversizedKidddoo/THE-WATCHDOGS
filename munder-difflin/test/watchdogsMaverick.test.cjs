'use strict';

/**
 * Maverick Skills Service & Approval Gate Independence Tests
 *
 * Verifies:
 *  1. Maverick owns the skill library; desks request via mailbox messages.
 *  2. Requested skills within a desk's manifest are served with full SKILL.md body.
 *  3. Requested skills outside a desk's manifest are refused and flagged to human.
 *  4. Requesting an offensive skill (e.g. SQLi) DOES NOT bypass or auto-approve
 *     requires_approval actions.
 *  5. Hard human approval gate remains 100% active and uncompromised.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const loadTs = require('./load-ts.cjs');

const { HiveManager } = loadTs('src/main/hive.ts');
const { MaverickSkillsService } = loadTs('src/main/maverick.ts');

async function createMaverickFloor(t) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'watchdogs-maverick-'));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const hive = new HiveManager(() => home);

  await hive.ensureAgent({ id: 'michael', name: 'Michael', provider: 'claude', cwd: home, isGod: true });
  await hive.ensureAgent({ id: 'chris', name: 'Chris', provider: 'strix', cwd: home });
  await hive.ensureAgent({ id: 'daniel', name: 'Daniel', provider: 'shannon', cwd: home });
  await hive.ensureAgent({ id: 'jonathan', name: 'Jonathan', provider: 'hackergpt', cwd: home });
  await hive.ensureAgent({ id: 'david', name: 'David', provider: 'hackbot', cwd: home });
  await hive.ensureAgent({ id: 'maverick', name: 'Maverick', provider: 'claude', cwd: home });

  return { home, hive };
}

test('Maverick: Desk queries skill within its manifest and receives full skill body', async (t) => {
  const { hive } = await createMaverickFloor(t);

  // Chris requests SQLi guidance from Maverick
  const queryMsg = {
    id: 'req-skill-chris-01',
    conversation: 'conv-maverick-1',
    in_reply_to: null,
    to: 'maverick',
    act: 'request',
    subject: 'Need guidance for SQL injection validation',
    body: 'exploiting-sql-injection-vulnerabilities'
  };

  hive.send(queryMsg, 'chris');

  // Chris's inbox must now contain the reply from Maverick
  const chrisInbox = hive.inbox('chris');
  assert.equal(chrisInbox.length, 1, 'Chris must receive reply from Maverick');
  assert.equal(chrisInbox[0].from, 'maverick');
  assert.equal(chrisInbox[0].act, 'inform');
  assert.match(chrisInbox[0].subject, /exploiting-sql-injection-vulnerabilities/);
  assert.match(chrisInbox[0].body, /## Workflow/);
  assert.match(chrisInbox[0].body, /sqlmap/);
});

test('Maverick: Desk queries skill outside its manifest and is refused/flagged', async (t) => {
  const { hive } = await createMaverickFloor(t);

  // Jonathan is recon desk; querying for an exploitation skill (outside its manifest)
  const unauthorizedQuery = {
    id: 'req-skill-jonathan-02',
    conversation: 'conv-maverick-2',
    in_reply_to: null,
    to: 'maverick',
    act: 'request',
    subject: 'Requesting forbidden skill',
    body: 'exploiting-sql-injection-vulnerabilities'
  };

  hive.send(unauthorizedQuery, 'jonathan');

  const jonathanInbox = hive.inbox('jonathan');
  assert.equal(jonathanInbox.length, 1);
  assert.equal(jonathanInbox[0].from, 'maverick');
  assert.equal(jonathanInbox[0].act, 'refuse');
  assert.match(jonathanInbox[0].body, /not in (\/)?jonathan's assigned manifest/);
  assert.match(jonathanInbox[0].body, /Flagged to human/);
});

test('Maverick & Approval Gate: Requesting offensive knowledge does NOT bypass action gate', async (t) => {
  const { hive } = await createMaverickFloor(t);

  // 1. Desk requests offensive skill guidance
  hive.send({
    id: 'req-skill-chris-03',
    conversation: 'conv-maverick-3',
    in_reply_to: null,
    to: 'maverick',
    act: 'request',
    subject: 'Need SSRF PoC workflow',
    body: 'exploiting-server-side-request-forgery'
  }, 'chris');

  // Skill arrives as knowledge
  assert.equal(hive.inbox('chris').length, 1);

  // 2. Desk attempts to launch actual exploitation action with requires_approval: true
  const exploitActionMsg = {
    id: 'exploit-action-04',
    conversation: 'conv-maverick-3',
    in_reply_to: null,
    to: 'chris',
    act: 'request',
    subject: 'Execute SSRF on metadata endpoint',
    body: 'Target http://169.254.169.254/latest/meta-data/',
    finding: {
      target: 'authorized.lab',
      phase: 'exploitation',
      finding_type: 'ssrf_poc',
      severity: 'critical',
      evidence: 'Cloud metadata access',
      source_desk: '/chris',
      requires_approval: true
    }
  };

  hive.send(exploitActionMsg, 'chris');

  // CRITICAL: Chris's inbox must still only have the 1 previous knowledge message!
  assert.equal(
    hive.inbox('chris').length,
    1,
    'Exploitation action MUST NOT enter inbox despite skill having been loaded!'
  );
  assert.equal(hive.approvalQueue.isPending('exploit-action-04'), true, 'Action must pause in approval queue');

  // 3. Human explicitly approves
  hive.approveMessage('exploit-action-04');
  assert.equal(hive.inbox('chris').length, 2, 'Delivered only after operator sign-off');
});
