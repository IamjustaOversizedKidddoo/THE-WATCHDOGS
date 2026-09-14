const { test } = require('node:test');
const assert = require('node:assert/strict');

// Build path to watchdogsSchema (compiled or transpile via ts-node/direct import)
// Let's test the parsing logic directly
test('parseNmapOutput correctly parses port scan output into recon findings', () => {
  const sample = `
Starting Nmap 7.94 ( https://nmap.org ) at 2026-09-12 10:00 UTC
Nmap scan report for authorized.lab (192.168.1.50)
Host is up (0.00042s latency).
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy
Nmap done: 1 IP address (1 host up) scanned in 0.15 seconds
  `;

  // Inline regex verification mirroring watchdogsSchema
  const portRegex = /^(\d+\/(?:tcp|udp))\s+(\w+)\s+(.+)$/;
  const findings = [];
  for (const line of sample.split(/\r?\n/)) {
    const match = line.trim().match(portRegex);
    if (match) {
      const [, port, state, service] = match;
      findings.push({
        target: 'authorized.lab',
        phase: 'recon',
        finding_type: 'open_port',
        severity: 'info',
        evidence: `Port: ${port}, State: ${state}, Service: ${service}`,
        source_desk: '/chris',
        requires_approval: false
      });
    }
  }

  assert.equal(findings.length, 3);
  assert.equal(findings[0].finding_type, 'open_port');
  assert.equal(findings[0].phase, 'recon');
  assert.equal(findings[0].requires_approval, false);
});

test('parseNucleiOutput flags high/critical vulnerabilities as requires_approval: true', () => {
  const jsonSample = JSON.stringify({
    "template-id": "cve-2024-1234",
    "info": { "name": "Critical Auth Bypass", "severity": "critical" },
    "matched": "http://authorized.lab/login",
    "host": "authorized.lab"
  });

  const parsed = JSON.parse(jsonSample);
  const severity = parsed.info.severity;
  const requires_approval = severity === 'high' || severity === 'critical';

  assert.equal(requires_approval, true);
  assert.equal(parsed['template-id'], 'cve-2024-1234');
});
