import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { TorControl, getExitRelay } from '../tor-check.mjs';

const EXIT = 'ABCDEF0123456789ABCDEF0123456789ABCDEF01';

async function fakeTor(replies) {
  const received = [];
  const server = net.createServer((socket) => {
    let buffer = '';
    socket.on('data', (data) => {
      buffer += data;
      let end;
      while ((end = buffer.indexOf('\r\n')) !== -1) {
        const command = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        received.push(command);
        const reply = replies(command) ?? ['510 Unrecognized command'];
        socket.write(reply.map((line) => `${line}\r\n`).join(''));
      }
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const control = await new TorControl('127.0.0.1', server.address().port).connect();
  return { control, received, close: () => { control.close(); server.close(); } };
}

test('parses data blocks whose lines look like status lines, and single-line values', async () => {
  const tor = await fakeTor((command) => {
    if (command === 'GETINFO circuit-status') {
      return [
        '650 STREAM 7 SUCCEEDED 250 example.com:443',
        '250+circuit-status=',
        '250 BUILT $1111111111111111111111111111111111111111~a,$' + EXIT + '~ExitNick PURPOSE=GENERAL',
        '251 BUILT $2222222222222222222222222222222222222222~b PURPOSE=GENERAL',
        '.',
        '250 OK',
      ];
    }
    if (command === `GETINFO ns/id/${EXIT}`) {
      return [`250+ns/id/${EXIT}=`, `r ExitNick q83v base 2026-10-06 12:00:00 203.0.113.7 9001 0`, 's Exit Fast Running Valid', '.', '250 OK'];
    }
    if (command === 'GETINFO status/bootstrap-phase') {
      return ['250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"', '250 OK'];
    }
  });
  const events = [];
  tor.control.onEvent((line) => events.push(line));
  try {
    assert.deepEqual(await getExitRelay(tor.control, '250'), { fingerprint: EXIT, nickname: 'ExitNick', ipv4: '203.0.113.7' });
    assert.deepEqual(events, ['650 STREAM 7 SUCCEEDED 250 example.com:443']);
    const [phase] = await tor.control.getInfo('status/bootstrap-phase');
    assert.match(phase, /PROGRESS=100/);
  } finally {
    tor.close();
  }
});

test('commandOk rejects error replies instead of hanging', async () => {
  const tor = await fakeTor((command) => command.startsWith('SETCONF') ? ['552 Unrecognized option'] : ['250 OK']);
  try {
    await assert.rejects(tor.control.commandOk('SETCONF Bogus=1'), /552 Unrecognized option/);
    await tor.control.commandOk('SIGNAL NEWNYM');
    assert.deepEqual(tor.received, ['SETCONF Bogus=1', 'SIGNAL NEWNYM']);
  } finally {
    tor.close();
  }
});
