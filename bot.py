"""Private Telegram attachment scanner. Python standard library only."""
import hashlib
import json
import logging
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request

MAX_BYTES = 20_000_000
LOG = logging.getLogger('scanner')
HELP = '''🛡 Virus Checker / ឧបករណ៍ស្កេនមេរោគ
ផ្ញើឯកសារជា File / Document ដើម្បីស្កេន (អតិបរមា 20 MB)។
Send any file as a Document (up to 20 MB).
/start /help — Help / ជំនួយ
/id — Your Telegram user ID
/status — Scanner version and signature date

Scans only files you send, not your phone or computer.
No detection does NOT guarantee safety. Unknown threats can be missed.
Encrypted archives and scan limits may prevent a complete scan.
Files pass through Telegram and this bot server. Local temporary copies are removed after scanning; Telegram copies remain.
មិនអាចរកមេរោគទាំងអស់ 100% បានទេ។'''

class TooLarge(Exception):
    pass


def download(url, destination):
    digest = hashlib.sha256()
    size = 0
    deadline = time.monotonic() + 120
    with urllib.request.urlopen(url, timeout=30) as response, open(destination, 'wb') as out:
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError('Download deadline')
            chunk = response.read(65536)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_BYTES:
                raise TooLarge()
            out.write(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def scan(path):
    try:
        result = subprocess.run([
            'clamscan', '--stdout', '--no-summary', '--infected',
            '--scan-archive=yes', '--alert-encrypted=yes',
            '--alert-exceeds-max=yes', '--max-filesize=25M',
            '--max-scansize=100M', '--max-recursion=12', '--max-files=1000',
            '--max-scantime=90000', str(path)
        ], capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return '⚠️ ស្កេនមិនបានសម្រេច / Scan failed or timed out. Safety is unknown.'
    if result.returncode == 0:
        return '✅ មិនបានរកឃើញមេរោគ / No threats detected by ClamAV. This is not a guarantee of safety.'
    if result.returncode == 1:
        signatures = [line.split(': ', 1)[-1].removesuffix(' FOUND')
                      for line in result.stdout.splitlines() if line.endswith(' FOUND')]
        if not signatures:
            return '⚠️ Scanner alert. Safety is unknown.'
        details = '\n'.join(signatures)[:1000]
        if any('Heuristics.Limits.' in s or 'Heuristics.Encrypted.' in s for s in signatures):
            return '⚠️ ស្កេនមិនពេញលេញ / Incomplete scan: encrypted content or scan limit. Safety is unknown.\n' + details
        return '🚨 រកឃើញការគំរាមកំហែង / Threat or suspicious content detected. Do not open the file.\n' + details
    return '⚠️ Scanner error. Safety is unknown. Check server logs and signature updates.'


class Bot:
    def __init__(self):
        token = os.environ.get('TELEGRAM_BOT_TOKEN', '').strip()
        if not token or token == 'PUT_BOTFATHER_TOKEN_HERE':
            raise ValueError('Set TELEGRAM_BOT_TOKEN in .env')
        self.base = 'https://api.telegram.org/bot' + token + '/'
        self.files = 'https://api.telegram.org/file/bot' + token + '/'
        self.allowed = {int(x.strip()) for x in os.environ.get('ALLOWED_USER_IDS', '').split(',') if x.strip()}
        self.last_scan = {}

    def api(self, method, **data):
        request = urllib.request.Request(self.base + method,
            data=json.dumps(data).encode(), headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.load(response)
        if not payload.get('ok'):
            raise RuntimeError('Telegram API rejected request')
        return payload['result']

    def say(self, chat, text):
        self.api('sendMessage', chat_id=chat, text=text[:4000])

    def handle(self, message):
        if message.get('chat', {}).get('type') != 'private':
            return
        chat = message['chat']['id']
        user = message.get('from', {}).get('id')
        command = message.get('text', '').split(' ', 1)[0].split('@', 1)[0]
        if command == '/id':
            self.say(chat, f'Your Telegram user ID: {user}')
            return
        if user not in self.allowed:
            self.say(chat, 'Access disabled. Send /id and add your ID to ALLOWED_USER_IDS in the server .env, then recreate the container.')
            return
        if command in ('/start', '/help'):
            self.say(chat, HELP)
            return
        if command == '/status':
            try:
                p = subprocess.run(['clamscan', '--version'], capture_output=True, text=True, timeout=10)
                text = p.stdout.strip() if p.returncode == 0 else 'Scanner unavailable'
                self.say(chat, text + '\nCheck the displayed signature date. Old definitions may miss newer threats.')
            except (OSError, subprocess.TimeoutExpired):
                self.say(chat, 'Scanner unavailable. Safety is unknown.')
            return
        document = message.get('document')
        if not document:
            self.say(chat, 'ផ្ញើជា File / Document ដើម្បីរក្សាឯកសារដើម។ Send as File / Document to scan the original bytes. /help')
            return
        if document.get('file_size', 0) > MAX_BYTES:
            self.say(chat, 'File too large. Maximum: 20 MB.')
            return
        if time.monotonic() - self.last_scan.get(user, -1000) < 15:
            self.say(chat, 'Please wait 15 seconds between scans.')
            return
        self.last_scan[user] = time.monotonic()
        self.say(chat, '🔎 កំពុងស្កេន / Scanning…')
        try:
            info = self.api('getFile', file_id=document['file_id'])
            if info.get('file_size', 0) > MAX_BYTES:
                raise TooLarge()
            with tempfile.TemporaryDirectory(prefix='tgscan-') as directory:
                # Never trust or execute the supplied filename.
                path = Path(directory) / 'sample.bin'
                size, digest = download(self.files + info['file_path'], path)
                verdict = scan(path)
            self.say(chat, f'{verdict}\n\nBytes: {size}\nSHA-256: {digest}\n\nLocal temporary file deleted.')
        except TooLarge:
            self.say(chat, 'File exceeds 20 MB. Scan not completed.')
        except Exception as error:
            # Exception strings can contain the bot token in a URL: never log them.
            LOG.warning('Attachment processing failed (%s)', type(error).__name__)
            self.say(chat, '⚠️ Download or scan failed. Safety is unknown. Try again later.')

    def run(self):
        self.api('deleteWebhook', drop_pending_updates=False)
        offset = 0
        LOG.info('Bot started; %s allowed users', len(self.allowed))
        while True:
            try:
                updates = self.api('getUpdates', offset=offset, timeout=30, allowed_updates=['message'], limit=10)
                for update in updates:
                    try:
                        self.handle(update.get('message', {}))
                    except Exception as error:
                        LOG.warning('Message failed (%s)', type(error).__name__)
                    offset = update['update_id'] + 1
            except Exception as error:
                LOG.warning('Polling failed (%s); retrying', type(error).__name__)
                time.sleep(5)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    Bot().run()
