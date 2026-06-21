# GuardianScan

Personal cybersecurity assistant — check if your email, password, phone, username, IP, or domain has appeared in known data breaches. Get a privacy score, RockYou password check, platform presence detection, and step-by-step data removal instructions.

## Quick Start

```bash
npm install
node server.js
```

Then open http://localhost:3000

## Requirements

- Node.js 18 or newer (uses built-in `fetch` — no extra packages needed)
- Internet connection (queries external breach APIs)
- No API keys required. Completely free to run.

## What it checks

| Type     | Sources |
|----------|---------|
| Email    | LeakCheck.io OSINT · HIBP catalog (700+ breaches) |
| Password | HIBP k-anonymity (14B+ records, password never sent in full) · RockYou top-500 wordlist |
| Phone    | LeakCheck.io · HIBP catalog |
| Username | LeakCheck.io · GitHub API · Reddit API (platform presence) |
| IP       | LeakCheck.io · HIBP catalog |
| Domain   | HIBP catalog (exact match) · LeakCheck.io |

## Privacy Score

Score is 0–100. **Higher = safer.**

| Score   | Grade     | Meaning |
|---------|-----------|---------|
| 90–100  | Excellent | No known threats |
| 75–89   | Good      | Minor exposure |
| 50–74   | Fair      | Action recommended |
| 25–49   | Poor      | Serious exposure |
| 0–24    | Critical  | Immediate action required |

When no breach is found, the score is still calculated from the credential's own patterns (length, character variety, common structures) to give an honest risk estimate.

## Files

```
server.js      Express API + static file hosting (all breach logic here)
index.html     Full React frontend — no build step, uses CDN
package.json   One dependency: express
.gitignore     Ignores node_modules and .env
README.md      This file
```

## API Endpoints

```
POST /api/breach/check    { "type": "email|password|username|phone|ip|domain", "value": "..." }
GET  /api/breach/catalog  Full HIBP breach catalog
GET  /api/breach/stats    Aggregate statistics
```

## Deploy anywhere

Works on Railway, Render, Fly.io, Heroku, or any VPS:

```bash
npm install
PORT=8080 node server.js
```

## Clone and run in VS Code

```bash
git clone https://github.com/YOUR_USERNAME/guardianscan.git
cd guardianscan
npm install
node server.js
# open http://localhost:3000
```

Open in VS Code directly:
```bash
git clone https://github.com/YOUR_USERNAME/guardianscan.git
cd guardianscan
code .
```

Then in the VS Code terminal: `npm install && node server.js`
