import net from 'node:net';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const EXE = process.platform === 'win32' ? '.exe' : '';
const TOR_BROWSER_ROOT = process.env.TOR_BROWSER_ROOT
  ? path.resolve(process.env.TOR_BROWSER_ROOT)
  : path.join(os.homedir(), 'Desktop', 'Tor Browser', 'Browser');
const FIREFOX = process.env.FIREFOX_PATH ?? path.join(TOR_BROWSER_ROOT, `firefox${EXE}`);
const TOR_EXECUTABLE = process.env.TOR_PATH ?? path.join(TOR_BROWSER_ROOT, 'TorBrowser', 'Tor', `tor${EXE}`);
const TOR_BUNDLE_DATA = process.env.TOR_GEOIP_DIR ?? path.join(TOR_BROWSER_ROOT, 'TorBrowser', 'Data', 'Tor');
const SESSIONS = Number.parseInt(process.env.SESSIONS ?? '10', 10);
const HEADLESS = process.env.HEADLESS === '1';
const SOCKS_HOST = '127.0.0.1';
const TARGET_URL = process.env.TARGET_URL ?? 'https://www.tiktok.com/';
const CHECK_URL = 'https://check.torproject.org/api/ip';
const CHECK_HOST = 'check.torproject.org';
// Tor ignores NEWNYM signals sent less than 10 seconds apart.
const NEWNYM_INTERVAL_MS = 10500;

// ---------------------------------------------------------------------------
// STEPS: run in order on TARGET_URL in every session once the page has fully loaded.
// Every step is the same: wait until the element is visible, click it, go to the next.
// A step written as { scrollIn, selector } first scrolls down inside the `scrollIn`
// container until `selector` shows up, then clicks it.
//
// Selectors are Puppeteer selectors: CSS, plus
//   'button::-p-text(Accept all)'       element containing that text
//   '::-p-aria(Search)'                 by accessible name
//   '::-p-xpath(//button[@id="x"])'     XPath
//   'host-element >>> button'           pierce into shadow DOM
// ---------------------------------------------------------------------------
const STEPS = [
  'STEP 1 SELECTOR',
  'STEP 2 SELECTOR',
  'STEP 3 SELECTOR',
  { scrollIn: 'STEP 4 CONTAINER SELECTOR', selector: 'STEP 4 BUTTON SELECTOR' },
];
const STEP_TIMEOUT_MS = 30000;
const STEP_ATTEMPTS = 3;

export class TorControl {
  constructor(host, port) {
    this.host = host;
    this.port = port;
    this.buffer = '';
    this.reply = [];
    this.inData = false;
    this.pending = [];
    this.listeners = new Set();
  }

  async connect() {
    this.socket = net.createConnection({ host: this.host, port: this.port });
    this.socket.on('data', (data) => this.onData(data));
    const failAll = (error) => {
      for (const item of this.pending.splice(0)) item.reject(error);
    };
    this.socket.on('error', failAll);
    this.socket.on('close', () => failAll(new Error('Tor control connection closed')));
    await new Promise((resolve, reject) => {
      this.socket.once('connect', resolve);
      this.socket.once('error', reject);
    });
    return this;
  }

  onEvent(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  onData(data) {
    this.buffer += data.toString('utf8');
    let end;
    while ((end = this.buffer.indexOf('\r\n')) !== -1) {
      const line = this.buffer.slice(0, end);
      this.buffer = this.buffer.slice(end + 2);
      this.onLine(line);
    }
  }

  // Replies are "NNN-" mid lines, "NNN+" data blocks terminated by ".", and a final "NNN " line.
  // Data block lines are never treated as status lines (a circuit id can be "250 ").
  onLine(line) {
    this.reply.push(line);
    if (this.inData) {
      if (line === '.') this.inData = false;
      return;
    }
    if (/^\d{3}\+/.test(line)) {
      this.inData = true;
      return;
    }
    if (!/^\d{3} /.test(line)) return;
    const lines = this.reply;
    this.reply = [];
    if (line.startsWith('650 ')) {
      for (const listener of this.listeners) listener(line, lines);
      return;
    }
    this.pending.shift()?.resolve(lines);
  }

  command(command) {
    return new Promise((resolve, reject) => {
      this.pending.push({ resolve, reject });
      this.socket.write(`${command}\r\n`);
    });
  }

  async commandOk(command) {
    const lines = await this.command(command);
    const status = lines.at(-1);
    if (!status.startsWith('250 ')) throw new Error(`Tor rejected "${command.split(' ')[0]}": ${status}`);
    return lines;
  }

  async authenticate(cookie) {
    await this.commandOk(`AUTHENTICATE ${cookie.toString('hex')}`);
  }

  async getInfo(key) {
    return valueLines(await this.commandOk(`GETINFO ${key}`), key);
  }

  close() {
    this.socket?.end();
  }
}

// GETINFO answers single-line values as "250-key=value" and multi-line values as a "250+key=" data block.
export function valueLines(lines, key) {
  const single = lines.find((line) => line.startsWith(`250-${key}=`));
  if (single !== undefined) {
    const value = single.slice(`250-${key}=`.length);
    return value ? [value] : [];
  }
  const first = lines.findIndex((line) => line.startsWith(`250+${key}=`));
  if (first < 0) throw new Error(`Tor did not return ${key}`);
  const result = [];
  for (const line of lines.slice(first + 1)) {
    if (line === '.') break;
    result.push(line.startsWith('..') ? line.slice(1) : line);
  }
  return result;
}

async function findFreePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const { port } = server.address();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function waitForExit(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise((resolve) => child.once('exit', resolve));
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function exists(file) {
  return fs.access(file).then(() => true, () => false);
}

async function startTorClient(runtimeDir, socksPort, controlPort) {
  const torDataDir = path.join(runtimeDir, 'tor-data');
  await fs.mkdir(torDataDir, { recursive: true });
  const cookieFile = path.join(torDataDir, 'control_auth_cookie');
  const defaultsFile = path.join(runtimeDir, 'empty-tor-defaults');
  const torrcFile = path.join(runtimeDir, 'torrc');
  // Tor on Windows only treats "C:\\..." (backslashes) as absolute, so keep native separators
  // and escape them inside the quoted torrc value.
  const torPath = (value) => `"${path.resolve(value).replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
  const geoip = path.join(TOR_BUNDLE_DATA, 'geoip');
  const geoip6 = path.join(TOR_BUNDLE_DATA, 'geoip6');
  await fs.writeFile(defaultsFile, '');
  await fs.writeFile(torrcFile, [
    `SocksPort ${SOCKS_HOST}:${socksPort}`,
    `ControlPort ${SOCKS_HOST}:${controlPort}`,
    'CookieAuthentication 1',
    `DataDirectory ${torPath(torDataDir)}`,
    ...(await exists(geoip) ? [`GeoIPFile ${torPath(geoip)}`] : []),
    ...(await exists(geoip6) ? [`GeoIPv6File ${torPath(geoip6)}`] : []),
    'DisableNetwork 0',
    'AvoidDiskWrites 1',
    'SafeLogging 1',
    'Log notice stdout',
    '',
  ].join('\n'));
  const torDir = path.dirname(TOR_EXECUTABLE);
  const tor = spawn(TOR_EXECUTABLE, ['--defaults-torrc', defaultsFile, '-f', torrcFile], {
    cwd: TOR_BROWSER_ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
    // The Linux bundle ships tor's shared libraries next to the binary.
    env: { ...process.env, LD_LIBRARY_PATH: [torDir, process.env.LD_LIBRARY_PATH].filter(Boolean).join(path.delimiter) },
  });
  let spawnError;
  const recentLogs = [];
  for (const stream of [tor.stdout, tor.stderr]) {
    stream?.on('data', (chunk) => {
      for (const line of chunk.toString('utf8').split(/\r?\n/).filter(Boolean)) {
        recentLogs.push(line);
        if (recentLogs.length > 8) recentLogs.shift();
        const progress = line.match(/Bootstrapped (\d+)%/);
        if (progress) console.log(`Tor bootstrap: ${progress[1]}%`);
        else if (/\[(?:warn|err)\]/i.test(line)) console.error(`Tor: ${line}`);
      }
    });
  }
  tor.on('error', (error) => { spawnError = error; });
  console.log('Starting the Tor client bundled with Tor Browser and waiting for the Tor network…');

  const started = Date.now();
  let lastProgress = -1;
  let controlFailures = 0;
  let control;
  while (Date.now() - started < 300000) {
    if (spawnError) {
      if (tor.pid != null) {
        tor.kill();
        await waitForExit(tor);
      }
      throw new Error(`Could not start the Tor client: ${spawnError.message}`);
    }
    if (tor.exitCode !== null) {
      throw new Error(`Tor client exited with code ${tor.exitCode}${recentLogs.length ? `: ${recentLogs.join(' | ')}` : ''}`);
    }
    try {
      if (!control) {
        const cookie = await fs.readFile(cookieFile);
        control = await new TorControl(SOCKS_HOST, controlPort).connect();
        await control.authenticate(cookie);
        console.log(`Tor controller authenticated on ${SOCKS_HOST}:${controlPort}.`);
      }
      const [phase = ''] = await control.getInfo('status/bootstrap-phase');
      const progress = Number(phase.match(/PROGRESS=(\d+)/)?.[1] ?? 0);
      if (progress !== lastProgress) {
        console.log(`Tor control reports bootstrap: ${progress}%`);
        lastProgress = progress;
      }
      if (progress === 100) return { tor, control };
    } catch (error) {
      controlFailures += 1;
      if (controlFailures <= 3) console.error(`Tor control retry: ${error.message}`);
      control?.close();
      control = undefined;
    }
    await delay(1000);
  }
  control?.close();
  tor.kill();
  await waitForExit(tor);
  throw new Error('Tor did not finish connecting within five minutes');
}

// Finds the circuit that carried a connection to `hostname` (any port, so http and https).
async function waitForStream(streams, hostname, timeoutMs = 30000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const match = streams.findLast((stream) => stream.status === 'SUCCEEDED'
      && stream.target.startsWith(`${hostname}:`) && stream.circuitId !== '0');
    if (match) return match;
    await delay(200);
  }
  throw new Error(`No Tor circuit was reported for ${hostname}`);
}

export async function getExitRelay(control, circuitId) {
  let row;
  const deadline = Date.now() + 10000;
  while (!row && Date.now() < deadline) {
    const rows = await control.getInfo('circuit-status');
    row = rows.find((line) => line.startsWith(`${circuitId} BUILT `));
    if (!row) await delay(500);
  }
  if (!row) throw new Error(`Tor circuit ${circuitId} is no longer available as BUILT`);

  const route = row.split(' ')[2];
  const lastHop = route.split(',').at(-1);
  const fingerprint = lastHop.match(/[A-F0-9]{40}/i)?.[0]?.toUpperCase();
  if (!fingerprint) throw new Error('Could not read the exit relay fingerprint from Tor');
  const nickname = lastHop.split(/[~=]/)[1] ?? '';

  const ns = await control.getInfo(`ns/id/${fingerprint}`);
  const relayLine = ns.find((line) => line.startsWith('r '));
  if (!relayLine) throw new Error(`Tor did not return a consensus record for ${fingerprint}`);
  const ipv4 = relayLine.split(/\s+/)[6];
  return { fingerprint, nickname, ipv4 };
}

// Keep every exit used so far out of future circuits, then ask Tor for fresh circuits.
async function rotateCircuits(control, usedExits, state) {
  if (usedExits.size > 0) {
    const excluded = [...usedExits.keys()].map((fingerprint) => `$${fingerprint}`).join(',');
    await control.commandOk(`SETCONF ExcludeExitNodes="${excluded}"`);
  }
  const wait = state.lastNewnym + NEWNYM_INTERVAL_MS - Date.now();
  if (wait > 0) await delay(wait);
  await control.commandOk('SIGNAL NEWNYM');
  state.lastNewnym = Date.now();
}

// Opens `url` the way a user following a link would: the page itself sets location.href.
// Puppeteer's page.goto() drives WebDriver BiDi's navigate command, which leaves sites like
// TikTok stuck loading in Tor Browser. Then waits until the new page reports
// readyState "complete" (fully loaded) and gives scripts a moment to render.
async function openUrl(page, url, timeoutMs = 120000) {
  const startUrl = page.url();
  const navigate = () => page.evaluate((target) => { window.location.href = target; }, url).catch(() => {});
  const readyState = () => page.evaluate(() => document.readyState).catch(() => 'navigating');
  await navigate();
  const started = Date.now();
  let lastLog = started;
  let retried = false;
  let state = 'navigating';
  while (Date.now() - started < timeoutMs) {
    await delay(500);
    const current = page.url();
    const moved = current !== startUrl && current.startsWith('http');
    state = await readyState();
    if (moved && state === 'complete') {
      await delay(2000);
      return;
    }
    if (!moved && !retried && Date.now() - started > 30000) {
      console.log('  Navigation has not started after 30s, trying again…');
      retried = true;
      await navigate();
    }
    if (Date.now() - lastLog >= 10000) {
      console.log(`  …still loading (${Math.round((Date.now() - started) / 1000)}s, ${state}) ${current}`);
      lastLog = Date.now();
    }
  }
  throw new Error(`${url} did not finish loading within ${timeoutMs / 1000}s (state: ${state}, at ${page.url()})`);
}

function visibleLocator(page, selector, timeout) {
  return page.locator(selector)
    .setTimeout(timeout)
    .setVisibility('visible')
    .setWaitForEnabled(true)
    .setEnsureElementIsInTheViewport(true)
    .setWaitForStableBoundingBox(true);
}

// Scrolls `containerSelector` down a bit at a time until `selector` is visible, leaving it on screen.
async function scrollUntilVisible(page, containerSelector, selector, timeout) {
  const deadline = Date.now() + timeout;
  const container = await visibleLocator(page, containerSelector, timeout).waitHandle();
  try {
    while (Date.now() < deadline) {
      const target = await page.$(selector);
      if (target) {
        await target.evaluate((element) => element.scrollIntoView({ block: 'center' }));
        const visible = await target.isVisible();
        await target.dispose();
        if (visible) return;
      }
      // Scroll most of a screenful, then give lazy-loaded content a moment to render.
      await container.evaluate((element) => element.scrollBy({ top: element.clientHeight * 0.8 }));
      await delay(700);
    }
  } finally {
    await container.dispose();
  }
  throw new Error(`"${selector}" did not appear while scrolling "${containerSelector}" within ${timeout}ms`);
}

async function runSteps(page) {
  for (const [index, step] of STEPS.entries()) {
    const { scrollIn, selector } = typeof step === 'string' ? { selector: step } : step;
    const label = `Step ${index + 1}/${STEPS.length} ${scrollIn ? `scroll "${scrollIn}" to ` : ''}"${selector}"`;
    let lastError;
    for (let attempt = 1; attempt <= STEP_ATTEMPTS; attempt += 1) {
      try {
        if (scrollIn) await scrollUntilVisible(page, scrollIn, selector, STEP_TIMEOUT_MS);
        await visibleLocator(page, selector, STEP_TIMEOUT_MS).click();
        lastError = undefined;
        break;
      } catch (error) {
        lastError = error;
        // A timeout means the element never became visible; retrying the same wait won't help.
        if (error.name === 'TimeoutError' || /did not appear/.test(error.message)) break;
        console.warn(`  ${label}: attempt ${attempt} failed (${error.message}), retrying…`);
        await delay(1000);
      }
    }
    if (lastError) throw new Error(`${label} failed: ${lastError.message}`);
    console.log(`  ${label}: clicked`);
    // Let any navigation or re-render the click triggered settle before the next step.
    await delay(500);
    await page.waitForFunction(() => document.readyState === 'complete', { timeout: 60000 }).catch(() => {});
  }
}

async function runSession(number, { control, socksPort, controlPort, runtimeDir, streams }) {
  const profileDir = await fs.mkdtemp(path.join(runtimeDir, `firefox-profile-${number}-`));
  streams.length = 0;
  let browser;
  try {
    const { default: puppeteer } = await import('puppeteer-core');
    browser = await puppeteer.launch({
      browser: 'firefox',
      protocol: 'webDriverBiDi',
      executablePath: FIREFOX,
      headless: HEADLESS,
      userDataDir: profileDir,
      timeout: 30000,
      // Without this Puppeteer has Firefox report every request and copy every response body
      // (up to 20 MB each) to the script, which bogs down heavy, video-streaming pages.
      networkEnabled: false,
      // Tell Tor Browser not to launch its own tor but to use ours, so it shows as connected
      // instead of holding pages at about:torconnect.
      env: {
        ...process.env,
        TOR_SKIP_LAUNCH: '1',
        TOR_SOCKS_HOST: SOCKS_HOST,
        TOR_SOCKS_PORT: String(socksPort),
        TOR_CONTROL_HOST: SOCKS_HOST,
        TOR_CONTROL_PORT: String(controlPort),
        TOR_CONTROL_COOKIE_AUTH_FILE: path.join(runtimeDir, 'tor-data', 'control_auth_cookie'),
      },
      extraPrefsFirefox: {
        'network.proxy.type': 1,
        'network.proxy.socks': SOCKS_HOST,
        'network.proxy.socks_port': socksPort,
        'network.proxy.socks_version': 5,
        'network.proxy.socks_remote_dns': true,
        'network.proxy.no_proxies_on': '',
        'network.proxy.failover_direct': false,
        'network.dns.disableIPv6': true,
        'network.trr.mode': 5,
        'media.peerconnection.enabled': false,
        'toolkit.telemetry.enabled': false,
        'datareporting.healthreport.uploadEnabled': false,
        // Show the IP check API as raw text instead of Firefox's JSON viewer.
        'devtools.jsonview.enabled': false,
        // Allow plain http sites: Tor Browser forces HTTPS-Only mode, which shows
        // "Secure Site Not Available" instead of loading them. Tor Browser always runs in
        // private browsing, so the _pbm variants are the ones that actually apply.
        'dom.security.https_only_mode': false,
        'dom.security.https_only_mode_pbm': false,
        'dom.security.https_only_mode_ever_enabled': false,
        'dom.security.https_only_mode_ever_enabled_pbm': false,
        'dom.security.https_first': false,
        'dom.security.https_first_pbm': false,
        // Lowest Tor Browser security level ("Standard"): all JavaScript and media enabled.
        'browser.security_level.security_slider': 4,
        'browser.security_level.security_custom': false,
        'javascript.enabled': true,
        // Let https pages load http subresources instead of blocking them.
        'security.mixed_content.block_active_content': false,
        'security.mixed_content.block_display_content': false,
        'security.mixed_content.upgrade_display_content': false,
      },
    });
    const page = await browser.newPage();

    console.log(`  Opening ${TARGET_URL} and waiting for it to fully load…`);
    let loadError;
    try {
      await openUrl(page, TARGET_URL);
    } catch (error) {
      // Still report the IP below: the connection worked even if the page is too slow over Tor.
      loadError = error;
    }
    const hostname = new URL(page.url().startsWith('http') ? page.url() : TARGET_URL).hostname;
    const title = await page.title().catch(() => '');
    const exit = await getExitRelay(control, (await waitForStream(streams, hostname)).circuitId);
    console.log(`  Visited ${page.url()}${title ? ` ("${title}")` : ''}`);
    console.log(`  >>> IP address used for ${hostname}: ${exit.ipv4}  (exit relay ${exit.nickname}, ${exit.fingerprint})`);
    if (loadError) throw new Error(`Page did not fully load, steps not run: ${loadError.message}`);
    await runSteps(page);

    // Tor Browser isolates circuits per site, so the check page may use a different circuit.
    await openUrl(page, CHECK_URL);
    const body = await page.evaluate(() => document.body.innerText);
    let result;
    try {
      result = JSON.parse(body);
    } catch {
      throw new Error(`Tor check returned unexpected content: ${body.slice(0, 200)}`);
    }
    if (result.IsTor !== true || typeof result.IP !== 'string') {
      throw new Error(`Tor check did not confirm a Tor exit IP: ${body.slice(0, 200)}`);
    }
    const checkExit = await getExitRelay(control, (await waitForStream(streams, CHECK_HOST)).circuitId);
    const sameCircuit = checkExit.fingerprint === exit.fingerprint;
    console.log(`  check.torproject.org confirms Tor, it saw IP ${result.IP}`
      + (sameCircuit ? ' (same exit relay)' : ` (separate circuit via ${checkExit.ipv4})`));
    return { ...exit, publicIp: result.IP, otherExits: sameCircuit ? [] : [checkExit.fingerprint] };
  } finally {
    await browser?.close().catch(() => {});
    await fs.rm(profileDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 })
      .catch((error) => console.error(`  Could not remove session profile: ${error.message}`));
  }
}

function printSummary(results) {
  console.log('\n=== Summary ===');
  const fingerprints = new Map();
  const ips = new Map();
  for (const result of results) {
    if (result.fingerprint) {
      fingerprints.set(result.fingerprint, (fingerprints.get(result.fingerprint) ?? 0) + 1);
      ips.set(result.ipv4, (ips.get(result.ipv4) ?? 0) + 1);
    }
  }
  for (const result of results) {
    const label = `Session ${String(result.number).padStart(2)}:`;
    if (result.error) {
      console.log(`${label} FAILED - ${result.error}`);
      continue;
    }
    const duplicate = fingerprints.get(result.fingerprint) > 1 || ips.get(result.ipv4) > 1;
    console.log(`${label} ${result.ipv4.padEnd(15)} ${result.fingerprint} ${duplicate ? 'DUPLICATE' : 'unique'}`);
  }
  const succeeded = results.filter((result) => !result.error);
  const allUnique = fingerprints.size === succeeded.length && ips.size === succeeded.length;
  console.log(`\n${succeeded.length}/${results.length} sessions succeeded; `
    + `${fingerprints.size} distinct exit relays, ${ips.size} distinct exit IPs.`);
  console.log(allUnique && succeeded.length === results.length
    ? 'PASS: every session used a unique exit relay.'
    : 'FAIL: not every session completed with a unique exit relay.');
  return allUnique && succeeded.length === results.length;
}

async function run() {
  if (!Number.isInteger(SESSIONS) || SESSIONS < 1) throw new Error('SESSIONS must be a positive integer');
  await fs.access(FIREFOX);
  await fs.access(TOR_EXECUTABLE);
  const runtimeDir = await fs.mkdtemp(path.join(os.tmpdir(), 'tor-puppeteer-'));
  const socksPort = await findFreePort();
  let controlPort = await findFreePort();
  while (controlPort === socksPort) controlPort = await findFreePort();
  let torClient;
  try {
    torClient = await startTorClient(runtimeDir, socksPort, controlPort);
  } catch (error) {
    await fs.rm(runtimeDir, { recursive: true, force: true });
    throw error;
  }
  const { tor, control } = torClient;
  const streams = [];
  const removeListener = control.onEvent((line) => {
    const match = line.match(/^650 STREAM (\d+) (\S+) (\d+) (\S+)/);
    if (match) streams.push({ id: match[1], status: match[2], circuitId: match[3], target: match[4] });
  });
  let interrupted = false;
  const onSigint = () => {
    if (interrupted) process.exit(130);
    interrupted = true;
    console.log('\nInterrupted: finishing the current session, press Ctrl+C again to force quit.');
  };
  process.on('SIGINT', onSigint);

  const results = [];
  const usedExits = new Map();
  const newnymState = { lastNewnym: 0 };
  try {
    await control.commandOk('SETEVENTS STREAM');
    console.log(`Tor is connected. Running ${SESSIONS} browser sessions, each on a new exit relay.`);
    for (let number = 1; number <= SESSIONS && !interrupted; number += 1) {
      console.log(`\n--- Session ${number}/${SESSIONS} ---`);
      try {
        await rotateCircuits(control, usedExits, newnymState);
        const exit = await runSession(number, { control, socksPort, controlPort, runtimeDir, streams });
        if (usedExits.has(exit.fingerprint)) {
          console.error(`  Exit relay ${exit.fingerprint} was already used in session ${usedExits.get(exit.fingerprint)}!`);
        } else {
          usedExits.set(exit.fingerprint, number);
        }
        for (const fingerprint of exit.otherExits) if (!usedExits.has(fingerprint)) usedExits.set(fingerprint, number);
        results.push({ number, ...exit });
      } catch (error) {
        console.error(`  Session ${number} failed: ${error.message}`);
        results.push({ number, error: error.message });
      }
    }
    if (!printSummary(results)) process.exitCode = 1;
  } finally {
    process.off('SIGINT', onSigint);
    removeListener();
    control.close();
    tor.kill();
    await waitForExit(tor);
    await fs.rm(runtimeDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 })
      .catch((error) => console.error(`Could not fully remove temporary files: ${error.message}`));
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  run().catch((error) => {
    console.error(`Automation failed: ${error.message}`);
    process.exitCode = 1;
  });
}
