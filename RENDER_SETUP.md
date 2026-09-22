# Render Free Setup / របៀបដាក់លើ Render Free

## 1. Update GitHub

1. Extract the ZIP on your computer.
2. Open `ThearithL/virus-checker` on GitHub, branch `main`.
3. Upload the **files inside** the extracted folder, not the ZIP itself.
4. Commit changes. The repository's first page must show `requirements.txt`,
   `app.py`, `bot.py`, `gunicorn.conf.py`, and `render.yaml` together.

កុំ Upload តែ ZIP។ ត្រូវ Extract ហើយ Upload ឯកសារខាងក្នុងទៅ GitHub។
`requirements.txt` ត្រូវនៅ root របស់ repository។

This replaces the old `bot.py`. Old `Dockerfile`, `compose.yaml`, and `start.sh`
are no longer needed for the Free Python version. Explicitly choose Python 3,
even if those old files remain in the repository. Do not run the old polling
bot elsewhere with this same token; it would conflict with the webhook.

## 2. Get the two API credentials

- **TELEGRAM_BOT_TOKEN:** the token for your bot from the official `@BotFather`.
- **VIRUSTOTAL_API_KEY:** create/sign in to your free VirusTotal Community
  account, then open your profile's **API key** page. See
  [the official instructions](https://docs.virustotal.com/reference/getting-started).

Save both values only in Render Environment or its Blueprint prompts. Do not
commit them to GitHub, paste them in a screenshot, or place them in a URL.

## 3A. Configure your existing Render service

Open the failed service, then **Settings → Build & Deploy**. Use these values:

| Setting | Value |
| --- | --- |
| Service type | Web Service |
| Language / Runtime | Python 3 |
| Branch | `main` |
| Root Directory | Empty, if the extracted files are at the repository root |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `gunicorn -c gunicorn.conf.py app:app` |
| Health Check Path | `/health` |
| Instance Type | **Free** |

An existing Start Command of `python bot.py` is also supported: it launches
Gunicorn with the same configuration. If the logs show `Application exited
early` after that command, deploy the latest commit containing this startup fix.

The `.python-version` file selects Python 3.12 with the current available patch.
If an old `PYTHON_VERSION` environment variable overrides it, remove that
override, or set a fully qualified supported Python 3.12 patch version.

If you keep the code inside a GitHub subfolder, set Root Directory to **that
exact folder containing `requirements.txt`**, for example `telegram-virus-checker`.
Do not put a ZIP filename in Root Directory.

Open **Environment** and add:

| Key | Value |
| --- | --- |
| `TELEGRAM_BOT_TOKEN` | Your BotFather token |
| `VIRUSTOTAL_API_KEY` | Your VirusTotal API key |
| `ALLOWED_USER_IDS` | Your Telegram numeric user ID, or `0` for initial setup |
| `WEBHOOK_SECRET` | A new random secret of at least 32 characters |

To generate a suitable secret on your computer, run this in PowerShell/Terminal
with Python installed:

```sh
python -c "import secrets; print(secrets.token_hex(32))"
```

Paste the generated value into `WEBHOOK_SECRET`. It is different from the bot
token. Only letters, numbers, `_` and `-` are accepted.

Render automatically supplies the service URL through `RENDER_EXTERNAL_URL`
and the HTTP port through `PORT`. You do not need to create either variable.

Save settings/environment changes and deploy the latest commit from `main`.
The webhook is registered automatically when Gunicorn's worker starts.

## 3B. Or create a new service through a Blueprint

Use this instead of 3A if you prefer automatic settings:

1. Render → **New → Blueprint** → connect `ThearithL/virus-checker`.
2. Branch: `main`; Blueprint path: `render.yaml` at repository root.
3. Enter the bot token, VirusTotal key, and allowed user ID (or `0`).
4. Confirm the service's compute is **Free**, then deploy.

The Blueprint sets the build/start commands, HTTP health check, and Free plan,
and generates `WEBHOOK_SECRET` for you. It does not automatically repair the old
service. Use the new service's logs and keep only one active service per token.

## 4. Authorize yourself and test

1. Watch Render logs for `Telegram webhook registered; ready for messages`.
2. Send `/id` in a private chat with your own bot.
3. If you used `0`, set `ALLOWED_USER_IDS` to the returned number in Render
   Environment. Save and redeploy so the change takes effect.
4. Send `/start`, then attach a harmless `.txt` file as **File / Document**.
5. The bot returns an existing VirusTotal report or says there is no report.
6. If you choose to share that file with VirusTotal, press **Upload to VirusTotal**.
   Read the privacy notice first. Wait about 30 seconds, then press **Check result**.

ផ្ញើ `/id` → ដាក់លេខ ID នៅ `ALLOWED_USER_IDS` → Save និង Redeploy
→ ផ្ញើ `/start` → ផ្ញើឯកសារសាកល្បង។

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `requirements.txt` not found | The file must be committed to the deployed branch, in the configured Root Directory. Extract and upload the files. |
| `Application exited early` after `python bot.py` | Deploy the latest commit, which starts Gunicorn from `bot.py`, or set Start Command to `gunicorn -c gunicorn.conf.py app:app`. |
| `No module named app` | `app.py` and `gunicorn.conf.py` must be beside `requirements.txt`; verify Root Directory. |
| Missing environment-variable error | Add the exact keys above; placeholder values will not work. |
| Webhook registration failed | Check the bot token, Render public HTTPS URL, and network access. Redeploy after fixing. |
| Access disabled | Send `/id`, update `ALLOWED_USER_IDS`, then redeploy. |
| Slow first response | Free services sleep after 15 minutes without inbound traffic; allow a cold start. |
| Quota reached / cooldown | Wait; free VirusTotal quota is shared by lookup, upload and status requests. |
| Hash not found | VirusTotal has no existing report; the file is not automatically safe or scanned. |
| Consent button expired | Re-send the file. Buttons expire after 15 minutes or a Render restart. |
| No result after a restart | The in-memory job may have been lost. Re-send for a hash lookup. |

The repo-access warning in your original log was not the failing step: the
checkout completed and pip ran. This version supplies the missing requirements
file and a real web-service entry point.

## Free means these limits still apply

Render Free can sleep and restart. VirusTotal Public API currently permits
4 requests/minute and 500/day and has non-commercial usage restrictions.
There is no local ClamAV engine in this version. Files are only submitted to
VirusTotal when you press the consent button, and submitted copies may be shared.

Sources: [Render Flask](https://render.com/docs/deploy-flask),
[Free service limits](https://render.com/docs/free),
[Root Directory](https://render.com/docs/monorepo-support),
[VirusTotal limits](https://docs.virustotal.com/reference/public-vs-premium-api),
[VirusTotal sharing](https://docs.virustotal.com/docs/how-it-works).
