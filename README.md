# puppettor

Drives Tor Browser's Firefox with Puppeteer through a private Tor client and checks that
every browser session leaves the Tor network through a different exit relay.

## What it does

1. Starts the `tor` binary bundled with Tor Browser (its own temporary data dir, SOCKS and
   control ports) and waits for it to bootstrap to 100%.
2. Runs `SESSIONS` (default 10) sessions. For each session it:
   - adds every exit relay used so far to `ExcludeExitNodes` and sends `SIGNAL NEWNYM`, so the
     session gets fresh circuits that can't end at a previously used exit;
   - launches Firefox with a fresh, throwaway profile, proxied through the Tor SOCKS port;
   - opens https://example.com/, reads the circuit that carried it from Tor's control port and
     prints the exit relay's IP, nickname and fingerprint;
   - opens https://check.torproject.org/api/ip to confirm the traffic is Tor and print the
     public IP the site saw;
   - closes the browser and deletes the profile.
3. Prints a summary and exits with code 1 if any session failed or reused an exit relay.

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
| `HEADLESS`         | unset (set to `1` to hide the browser window)   |

`npm test` runs unit tests for the Tor control-port client against a fake control server.
