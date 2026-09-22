# Telegram Virus Checker — Render Free

Bot ពិនិត្យឯកសារ ដែលអាចដាក់លើ **Render Free Web Service**។

This version uses **Telegram webhooks + VirusTotal API**, with Flask and Gunicorn.
It replaces the previous local ClamAV scanner, which needed much more RAM. It is
for your private, non-commercial personal use with VirusTotal's Public API.

**Main change:** `requirements.txt` is included, and the service listens on
Render's HTTP port. Choose **Python 3 + Web Service + Free**. The old Docker
Background Worker settings are not used by this version.

## Deploy / របៀប Deploy

See [RENDER_SETUP.md](RENDER_SETUP.md) for exact steps.

1. Extract this ZIP and upload its contents to the GitHub repository root.
2. In Render choose **New → Blueprint**, connect the repo and select `main`.
3. Supply `TELEGRAM_BOT_TOKEN`, `VIRUSTOTAL_API_KEY`, and `ALLOWED_USER_IDS`.
   The Blueprint generates `WEBHOOK_SECRET` automatically and selects Free.
4. Wait for `Telegram webhook registered; ready for messages` in logs.
5. Send `/id`, authorize that ID in Render Environment if necessary, then send
   `/start` and a harmless text document.

For an existing Python Web Service, use the manual configuration in the setup
guide. Uploading `render.yaml` alone does not apply settings to that existing
service; you must create/sync a Blueprint or edit the service settings yourself.

## Commands

The bot registers its Telegram command Menu automatically on startup. After
deploying, send `/start` or `/menu` to show the Khmer/English buttons: Scan,
Hash, My ID, Status, Help, and Privacy. If hidden, use Telegram's keyboard icon
or send `/menu` again. Scan explains how to attach a document; Hash explains
the `/hash SHA256` command. Scanning still requires an allowed user ID.

| Command / action | Behavior |
| --- | --- |
| `/start`, `/help` | Khmer + English help |
| `/menu` | Show the main buttons |
| `/scan` | Instructions for attaching a file |
| `/id` | Your numeric Telegram user ID, even before authorization |
| `/status` | Bot configuration summary; no API key is exposed |
| `/privacy` | How Telegram, Render and VirusTotal handle your file |
| `/hash <SHA256>` | Retrieve an existing report by a 64-character hash |
| Send File / Document | Download up to 20 MB, hash it, delete local copy, look up hash |
| Upload to VirusTotal button | With your consent, re-download the same file, verify the hash, upload for analysis |
| Check result button | Retrieve analysis status; wait 30 seconds between checks |
| Cancel button | Discard the pending upload request |

The allowlist is required for scans. Empty `ALLOWED_USER_IDS` or `0` disables
scanning for real users; `/id` and `/privacy` still work. Multiple IDs can be
separated with commas. The bot ignores group chats.

Scan reports, hash-not-found messages, and analysis progress are displayed in Khmer.
SHA-256 hashes, VirusTotal links, numeric counts, and UTC timestamps are preserved.

## What the result means

- **Existing report:** results from a previous VirusTotal analysis, with its date.
  A hash match does not perform a new scan. Hash not found means no verdict.
- **Malicious / suspicious reports:** some engines flagged the file. False
  positives can occur; do not open an untrusted file to check for yourself.
- **No detections:** not proof of safety. Unknown threats, encrypted archives,
  unsupported formats and missed detections remain possible. Engine failures and
  unsupported types are counted separately. No usable results means unknown.
- **Queued / in progress:** no final verdict yet. Tap Check result later.
- **API error / quota / timeout:** the scan or lookup did not complete; never
  treat it as a clean result.

មិនអាចរកឃើញមេរោគគ្រប់ប្រភេទ 100% បានទេ។ Bot ពិនិត្យតែឯកសារដែលអ្នកផ្ញើ
មិនស្កេនឧបករណ៍ទាំងមូល និងមិនលុបមេរោគពីកុំព្យូទ័រទេ។

## Privacy / ឯកជនភាព

Attachments pass through Telegram and Render. Initially the bot sends only the
SHA-256 hash to VirusTotal, not the contents or original filename. Use `/hash`
if you do not want to send a document through Telegram/Render at all. Hashes
still disclose which known file is being checked.

**Only pressing the explicit Upload to VirusTotal button submits file contents.**
The prompt names VirusTotal and explains retention and sharing. Files submitted
to the public service may be retained and shared with security partners and
premium customers; reports are shared publicly. Do not submit passwords, private
documents, source code you cannot share, or other confidential data. This bot
cannot remove copies from Telegram or VirusTotal.

ចុច **Upload to VirusTotal** ទើបផ្ញើឯកសារទៅ VirusTotal។ ឯកសារអាចត្រូវបាន
រក្សាទុក និងចែករំលែក។ កុំ Upload ឯកសារសម្ងាត់។

Render copies are temporary files, removed after each handled download/upload
operation. The bot never runs or extracts uploaded programs. Consent is bound
to the requesting user, chat, and SHA-256; it expires after 15 minutes. Pending
state contains metadata, not file contents. Restarting or sleeping loses it.

## Free-plan limits

- Render Free sleeps after 15 minutes without inbound traffic. Telegram webhook
  requests can wake it; the first reply may take about a minute or longer.
- VirusTotal Public API currently allows **4 requests/minute and 500/day**.
  Hash lookup, upload, and each result check are separate requests. The bot
  spaces requests 16 seconds apart, enforces a 30-second result-check interval,
  and reports quota errors. Quotas are shared with any other use of your API key.
- The API is for non-commercial use and has other usage restrictions. This is
  a small private bot, not a public scanning service or business antivirus.
- Use **one Gunicorn worker / one instance**. It has one scan thread and a queue
  of four updates to keep memory use bounded. A full queue returns HTTP 503 so
  Telegram can retry. Up to 20 MB per document is supported.
- Jobs, duplicate-update records and consent buttons are kept in memory. If
  Render restarts after a webhook is acknowledged, an accepted job/result can be
  lost. Re-send the document for a hash lookup. This is not a durable job system.
- No database, persistent disk, ClamAV daemon, background worker subscription,
  or artificial keep-alive pinger is required.

## Validation

Verified during preparation: all 20 offline tests passed. Gunicorn started with
Render-style preload settings, `/health` returned HTTP 200, and webhook requests
returned 403 without the secret and 200 with it. No real Telegram messages or
VirusTotal submissions were sent, and no live Render deployment was performed.

Install `requirements.txt`, then run `python -m unittest -v`.
The tests mock external services and cover webhook authentication, authorization,
size limits, quota errors, duplicate delivery, backpressure, file cleanup, report
classification, and per-file upload consent. They send no files or messages.

A local HTTP startup test can verify Gunicorn and `/health`. These tests do not
establish antivirus detection accuracy or guarantee a Render deployment. A live
check needs your own bot token and VirusTotal API key. Start with a harmless text
file; do not use live malware for testing.

## Official documentation

- [Render Flask deployment](https://render.com/docs/deploy-flask)
- [Render Free limits](https://render.com/docs/free)
- [Python version selection](https://render.com/docs/python-version)
- [Telegram webhook API](https://core.telegram.org/bots/api#setwebhook)
- [VirusTotal API key](https://docs.virustotal.com/reference/getting-started)
- [Public API limits and restrictions](https://docs.virustotal.com/reference/public-vs-premium-api)
- [VirusTotal sharing policy](https://docs.virustotal.com/docs/how-it-works)
