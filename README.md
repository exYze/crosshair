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

```powershell
node 'D:\Program Files\nodejs\node_modules\npm\bin\npm-cli.js' install
docker compose up -d postgres
node 'D:\Program Files\nodejs\node_modules\npm\bin\npm-cli.js' start
```

The normal `npm` command on this workstation points at a missing roaming install, so the direct npm CLI path above is the reliable launcher.

## Configure

1. Open Settings.
2. Add authorized targets, one per line.
3. Install recon tools on the workstation (this repo does not ship binaries), then set their paths in Settings.
4. Enable local recon tools.
5. Use the local Postgres connection string while testing: `postgres://aip:aip_dev_password@localhost:5432/crosshair`.
6. For a remote Postgres server later, replace the connection string in Settings and keep storage enabled.
7. Use Test DB to create or verify the evidence schema.
8. Add OpenAI-compatible API settings for the chat assistant.

If Nmap is not in the system PATH, set `Nmap Path` to the full executable path, such as `C:\Program Files\Nmap\nmap.exe`.

## Local Postgres

The local test database runs in Docker from [docker-compose.yml](E:/AIP/docker-compose.yml).

```powershell
docker compose up -d postgres
docker compose ps
docker compose logs -f postgres
```

The container publishes Postgres on `localhost:5432` by default. You can override database, user, password, or port with the variables listed in [.env.example](E:/AIP/.env.example).

To stop the database without deleting stored data:

```powershell
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
