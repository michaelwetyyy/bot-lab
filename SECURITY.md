# Security policy

## Scope

Bot Lab is an authorised defensive experiment. It measures browser-provided
signals and verifies proof-of-work challenges on infrastructure controlled by
the operator. It is not an authentication factor, identity system, or anti-bot
bypass tool.

## Data boundary

- Fingerprint collection starts only after an explicit user action.
- Raw FingerprintJS components remain in the browser.
- The server receives the FingerprintJS identifier and immediately transforms
  it with an ephemeral HMAC key before storing a 16-character experiment tag.
- The Bot Lab application uses client addresses only as input to ephemeral
  rate-limit keys and never retains or returns the raw value.
- The dedicated security gateway may retain an address inside the homelab for
  a CrowdSec decision or alert. Its database is ephemeral, entries are flushed
  within 24 hours, online community signal sharing is disabled, and addresses
  are excluded from experiment reports. Pull-only community intelligence does
  not contribute local attack signals.
- Gateway access logging is disabled. Anubis runs at error log level and its
  state is ephemeral.
- Observations expire after 15 minutes and are capped at 500 records.
- Restarting the process deletes every observation and invalidates every
  outstanding challenge.

## Reporting

Report vulnerabilities privately to the repository owner. Do not include
visitor identifiers, IP addresses, browser histories, credentials, or data
collected from people who did not knowingly participate in the lab.
