# Crosshair Terminal

Electron desktop app for an authorized Crosshair assessment console.

## What is built

- Left-side AIP-style chat workspace.
- Right-side network map populated from completed recon runs.
- Recon tool profiles for Nmap, Amass, Naabu, and HTTPX.
- Offline ATT&CK knowledge base under `data/attack-kb`.
- Postgres evidence storage for recon runs and findings.
- Settings screen for OpenAI-compatible chat APIs:
  - API base URL
  - API key
  - model name
  - optional organization
- Local recon tools, disabled by default until explicitly enabled.
- Configured target scope guardrails before any local tool execution.
- Per-action operator approval before recon, validation planning, and retest planning.

## Guardrails

This app is designed for authorized defensive validation. The current build does not ship automated exploitation, privilege-escalation payloads, credential theft, stealth, or real data exfiltration features. Validation and retest actions create operator-reviewed plans and evidence workflows.

## Run

```sh
npm install
docker compose up -d postgres
npm start
```

Crosshair is an Electron app and is intended to run on Windows, Linux, and macOS with a current Node.js LTS release, npm, Docker Desktop or Docker Engine, and any recon tools you choose to enable.

## Configure

1. Open Settings.
2. Add authorized targets, one per line.
3. Install recon tools on the workstation (this repo does not ship binaries), then set their paths in Settings.
4. Enable local recon tools.
5. Use the local Postgres connection string while testing: `postgres://aip:aip_dev_password@localhost:5432/crosshair`.
6. For a remote Postgres server later, replace the connection string in Settings and keep storage enabled.
7. Use Test DB to create or verify the evidence schema.
8. Add OpenAI-compatible API settings for the chat assistant.

If a recon tool is not in the system `PATH`, set its full executable path in Settings. Examples include `C:\Program Files\Nmap\nmap.exe` on Windows, `/opt/homebrew/bin/nmap` on macOS, or `/usr/bin/nmap` on Linux.

## Recon Tools

Crosshair does not ship Nmap, Amass, Naabu, or HTTPX binaries. Install only the tools you plan to use on each workstation, then either leave the Settings path as the command name when the tool is on `PATH`, or provide the full path to the executable.

- Windows: install Nmap from `nmap.org`; install ProjectDiscovery tools from their releases or your preferred package manager.
- macOS: install common tools with Homebrew, such as `brew install nmap amass`.
- Linux: install tools with your distribution package manager, Snap, Homebrew on Linux, or vendor release binaries.

## Local Postgres

The local test database runs in Docker from [docker-compose.yml](docker-compose.yml).

```sh
docker compose up -d postgres
docker compose ps
docker compose logs -f postgres
```

The container publishes Postgres on `localhost:5432` by default. You can override database, user, password, or port with the variables listed in [.env.example](.env.example).

To stop the database without deleting stored data:

```sh
docker compose down
```

The database data is stored in the named Docker volume `aip-postgres-data`.

## Postgres Schema

The app creates two tables when Test DB runs or when recon evidence is saved:

- `recon_runs`
- `findings`

## Recommended Next Decisions

1. Decide whether recon results should reload from Postgres on app start.
2. Add authenticated inventory sources for asset ownership.
3. Add report export and evidence attachment workflows.
4. Expand the offline ATT&CK knowledge base from official STIX data.
