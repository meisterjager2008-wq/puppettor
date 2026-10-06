# puppettor

Drives Tor Browser's Firefox with Puppeteer through a private Tor client and checks that
every browser session leaves the Tor network through a different exit relay.

## What it does

1. Starts the `tor` binary bundled with Tor Browser (its own temporary data dir, SOCKS and
   control ports) and waits for it to bootstrap to 100%.
2. Runs `SESSIONS` (default 10) sessions. For each session it:
   - adds every exit relay used so far to `ExcludeExitNodes` and sends `SIGNAL NEWNYM`, so the
     session gets fresh circuits that can't end at a previously used exit;
   - launches Firefox with a fresh, throwaway profile, pointed at our Tor client (Tor Browser
     skips its own launcher via `TOR_SKIP_LAUNCH` and connects to our control port);
   - opens `TARGET_URL` (https://www.tiktok.com/ by default), reads the circuit that carried it from Tor's control port and
     prints the exit relay's IP, nickname and fingerprint;
   - waits for the page to fully load (load event, `readyState` complete, network quiet), then
     runs the `STEPS` list in order (see below);
   - opens https://check.torproject.org/api/ip to confirm the traffic is Tor and print the
     public IP the site saw;
   - closes the browser and deletes the profile.
3. Prints a summary and exits with code 1 if any session failed or reused an exit relay.

## Page steps

Edit the `STEPS` array near the top of `tor-check.mjs`; each entry runs in order on the target
page in every session. Element steps wait until the element is visible, enabled, scrolled into
view and stable before acting, and retry if the page re-renders it.

```js
const STEPS = [
  { name: 'Accept cookies', action: 'click', selector: 'button::-p-text(Accept all)', optional: true },
  { action: 'click', selector: '#search-button' },
  { action: 'type', selector: 'input[type="search"]', text: 'cats' },
  { action: 'press', key: 'Enter' },
  { action: 'waitFor', selector: '[data-e2e="search-results"]', timeout: 60000 },
  { action: 'sleep', ms: 3000 },
];
```

A failing step (unless `optional: true`) marks the session failed and moves on to the next one.

## Usage

```sh
npm install
npm start
```

Configuration (environment variables):

| Variable           | Default                                         |
| ------------------ | ----------------------------------------------- |
| `TOR_BROWSER_ROOT` | `~/Desktop/Tor Browser/Browser`                 |
| `FIREFOX_PATH`     | `$TOR_BROWSER_ROOT/firefox(.exe)`               |
| `TOR_PATH`         | `$TOR_BROWSER_ROOT/TorBrowser/Tor/tor(.exe)`    |
| `TOR_GEOIP_DIR`    | `$TOR_BROWSER_ROOT/TorBrowser/Data/Tor`         |
| `SESSIONS`         | `10`                                            |
| `TARGET_URL`       | `https://www.tiktok.com/`                       |
| `HEADLESS`         | unset (set to `1` to hide the browser window)   |

`npm test` runs unit tests for the Tor control-port client against a fake control server.
