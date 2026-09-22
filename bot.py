"""Private Telegram webhook bot: hash lookup, then explicitly consented uploads."""
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import logging
import os
from pathlib import Path
import queue
import re
import secrets
import tempfile
import threading
import time
from urllib.parse import quote, urlsplit

import requests

MAX_BYTES = 20_000_000
PENDING_TTL = 15 * 60
LOG = logging.getLogger('virus_checker')
SHA256 = re.compile(r'[a-fA-F0-9]{64}')

PRIVACY = '''🔒 Privacy / ឯកជនភាព
ឯកសារឆ្លងកាត់ Telegram និង Render។ ដំបូង bot ផ្ញើតែ SHA-256 hash ទៅ VirusTotal ដើម្បីរករបាយការណ៍ចាស់។
Files pass through Telegram and Render. Initially only the SHA-256 hash is sent to VirusTotal to look up an existing report.

Only tapping “Upload to VirusTotal” sends the file contents to VirusTotal. Uploaded files may be retained and shared with security partners and premium customers; reports are shared publicly. Do not upload confidential files. This bot cannot delete VirusTotal or Telegram copies.
ចុច “Upload to VirusTotal” ទើបផ្ញើឯកសារទៅ VirusTotal។ ឯកសារអាចត្រូវបានរក្សាទុក និងចែករំលែក។ កុំ Upload ឯកសារសម្ងាត់។

Temporary Render copies are removed after each handled operation. Pending buttons expire after 15 minutes or a service restart.'''

HELP = '''🛡 Virus Checker — Render Free
ផ្ញើ File / Document (អតិបរមា 20 MB) ដើម្បីពិនិត្យ។
Send a File / Document (maximum 20 MB) for a hash lookup.
If needed, you can consent to upload it to VirusTotal for analysis.

/id — Your Telegram user ID
/hash SHA256 — Look up a hash without sending the file
/status — Bot status
/privacy — File sharing and retention
/help — This message

មិនអាចធានារកឃើញមេរោគគ្រប់ប្រភេទ 100% ទេ។
No detections is not a guarantee of safety. This checks submitted files, not your whole device.
Free hosting may sleep; allow about a minute for the first reply. API quota can delay or limit checks.'''


class UserError(Exception):
    """Only fixed, non-secret messages from this exception may be sent to users."""


@dataclass(frozen=True)
class Settings:
    token: str
    vt_key: str
    allowed: frozenset
    secret: str
    base_url: str

    @classmethod
    def from_env(cls):
        token = os.environ.get('TELEGRAM_BOT_TOKEN', '').strip()
        key = os.environ.get('VIRUSTOTAL_API_KEY', '').strip()
        secret = os.environ.get('WEBHOOK_SECRET', '').strip()
        base = os.environ.get('RENDER_EXTERNAL_URL', '').strip().rstrip('/')
        if not token or token == 'YOUR_BOTFATHER_TOKEN':
            raise ValueError('Set TELEGRAM_BOT_TOKEN in Render Environment')
        if not key or key == 'YOUR_VIRUSTOTAL_API_KEY':
            raise ValueError('Set VIRUSTOTAL_API_KEY in Render Environment')
        if not re.fullmatch(r'[A-Za-z0-9_-]{32,256}', secret) or secret.startswith('REPLACE_'):
            raise ValueError('Set WEBHOOK_SECRET to a random 32-256 character value (letters, numbers, _ or -)')
        try:
            allowed = frozenset(int(x.strip()) for x in os.environ.get('ALLOWED_USER_IDS', '').split(',') if x.strip())
        except ValueError:
            raise ValueError('ALLOWED_USER_IDS must contain numeric IDs separated by commas') from None
        if base:
            parts = urlsplit(base)
            if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment or parts.path:
                raise ValueError('RENDER_EXTERNAL_URL must be an HTTPS origin without a path')
        elif os.environ.get('RENDER') == 'true':
            raise ValueError('Use a Render Web Service; RENDER_EXTERNAL_URL is required')
        return cls(token, key, allowed, secret, base)


class Telegram:
    def __init__(self, token):
        self.api_base = 'https://api.telegram.org/bot' + token + '/'
        self.file_base = 'https://api.telegram.org/file/bot' + token + '/'

    def call(self, method, **data):
        # Never log exceptions from requests: their URLs can include the token.
        with requests.post(self.api_base + method, json=data, timeout=(10, 30), allow_redirects=False) as response:
            if response.status_code != 200:
                raise UserError('Telegram request failed. Please try again later.')
            body = response.json()
            if not isinstance(body, dict) or not body.get('ok'):
                raise UserError('Telegram rejected the request. Please try again later.')
            return body.get('result')

    def say(self, chat, text, keyboard=None):
        fields = dict(chat_id=chat, text=text[:4000], link_preview_options={'is_disabled': True})
        if keyboard:
            fields['reply_markup'] = {'inline_keyboard': keyboard}
        return self.call('sendMessage', **fields)

    def download(self, file_id, path):
        info = self.call('getFile', file_id=file_id)
        if info.get('file_size', 0) > MAX_BYTES:
            raise UserError('File is too large. Maximum: 20 MB.')
        remote_path = info.get('file_path', '')
        if not remote_path or remote_path.startswith('/') or '..' in remote_path.split('/') or '://' in remote_path:
            raise UserError('Telegram file is unavailable.')
        digest = hashlib.sha256()
        size = 0
        deadline = time.monotonic() + 120
        url = self.file_base + quote(remote_path, safe='/')
        with requests.get(url, stream=True, timeout=(10, 30), allow_redirects=False) as response:
            if response.status_code != 200:
                raise UserError('File download failed. Safety is unknown.')
            with open(path, 'wb') as output:
                for chunk in response.iter_content(chunk_size=65536):
                    if time.monotonic() > deadline:
                        raise UserError('File download timed out. Safety is unknown.')
                    size += len(chunk)
                    if size > MAX_BYTES:
                        raise UserError('File is too large. Maximum: 20 MB.')
                    output.write(chunk)
                    digest.update(chunk)
        return digest.hexdigest(), size


class VirusTotal:
    def __init__(self, key):
        self.key = key
        self.next_call = 0.0
        self.cooldown = 0.0

    def request(self, method, path, missing_ok=False, **kwargs):
        # All calls run on one consumer thread. Space starts 16 seconds apart.
        now = time.monotonic()
        if now < self.cooldown:
            raise UserError('VirusTotal quota/cooldown is active. Please try later. Safety is unknown.')
        time.sleep(max(0, self.next_call - now))
        self.next_call = time.monotonic() + 16
        with requests.request(method, 'https://www.virustotal.com/api/v3/' + path,
                              headers={'x-apikey': self.key}, timeout=(10, 90),
                              allow_redirects=False, **kwargs) as response:
            if response.status_code == 404 and missing_ok:
                return None
            if response.status_code == 429:
                retry = response.headers.get('Retry-After', '')
                delay = int(retry) if retry.isdigit() else 60
                self.cooldown = time.monotonic() + max(60, delay)
                raise UserError('VirusTotal quota reached. Please try later; daily limits may require waiting until reset. Safety is unknown.')
            if response.status_code in (401, 403):
                raise UserError('VirusTotal API key is invalid or lacks access. Check Render Environment.')
            if response.status_code not in (200, 201):
                raise UserError('VirusTotal is unavailable or rejected the request. Safety is unknown.')
            body = response.json()
            if not isinstance(body, dict) or not isinstance(body.get('data'), dict):
                raise UserError('VirusTotal returned an incomplete response. Safety is unknown.')
            return body['data']

    def lookup(self, digest):
        result = self.request('GET', 'files/' + digest, missing_ok=True)
        if result is not None and result.get('id') != digest:
            raise UserError('VirusTotal returned a mismatched report. Safety is unknown.')
        return result

    def upload(self, path):
        with open(path, 'rb') as sample:
            result = self.request('POST', 'files', files={'file': ('sample.bin', sample, 'application/octet-stream')})
        analysis_id = result.get('id')
        if not isinstance(analysis_id, str) or not analysis_id or len(analysis_id) > 512:
            raise UserError('File may have been uploaded, but no analysis ID was returned. Try its hash later.')
        return analysis_id

    def analysis(self, analysis_id):
        return self.request('GET', 'analyses/' + quote(analysis_id, safe=''))


def report_text(attributes, digest, fresh=False):
    stats = attributes.get('stats' if fresh else 'last_analysis_stats', {})
    if not isinstance(stats, dict) or any(type(value) is not int or value < 0 for value in stats.values()):
        return '⚠️ Invalid analysis statistics. Safety is unknown.'
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    tested = sum(stats.get(k, 0) for k in ('malicious', 'suspicious', 'undetected', 'harmless'))
    skipped = sum(stats.get(k, 0) for k in ('failure', 'timeout', 'confirmed-timeout', 'type-unsupported'))
    if malicious:
        verdict = '🚨 Engines reported malicious content / រកឃើញការគំរាមកំហែង។ Do not open the file.'
    elif suspicious:
        verdict = '⚠️ Engines reported suspicious content / ឯកសារគួរឱ្យសង្ស័យ។'
    elif tested == 0:
        verdict = '⚠️ No usable engine results / មិនមានលទ្ធផលគ្រប់គ្រាន់។ Safety is unknown.'
    else:
        verdict = 'ℹ️ No detections in returned engine results / មិនបានរកឃើញក្នុងរបាយការណ៍នេះ។'
    timestamp = attributes.get('date' if fresh else 'last_analysis_date')
    try:
        date = datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    except (ValueError, TypeError, OverflowError, OSError):
        date = 'unknown'
    coverage = f'Engines with results: {tested}; failed/unsupported/timed out: {skipped}.'
    if skipped:
        coverage += ' Coverage is incomplete.'
    source = 'Submitted analysis' if fresh else 'Existing report — not a new scan'
    return (f'{verdict}\n{source}\nMalicious: {malicious} | Suspicious: {suspicious}\n'
            f'{coverage}\nAnalysis date: {date}\n'
            'No detections does not guarantee safety. False positives and missed threats are possible.\n'
            f'\nSHA-256: {digest}\nhttps://www.virustotal.com/gui/file/{digest}')


class Checker:
    def __init__(self, settings):
        self.settings = settings
        self.tg = Telegram(settings.token)
        self.vt = VirusTotal(settings.vt_key)
        self.jobs = queue.Queue(maxsize=4)
        self.lock = threading.Lock()
        self.seen = OrderedDict()
        self.pending = OrderedDict()
        self.last_request = {}
        self.registered = False
        self.started = False

    def start(self):
        with self.lock:
            if self.started:
                return
            self.started = True
        threading.Thread(target=self.consume, name='checker', daemon=True).start()
        threading.Thread(target=self.register, name='webhook-registration', daemon=True).start()

    def register(self):
        if not self.settings.base_url:
            LOG.warning('No RENDER_EXTERNAL_URL; automatic webhook registration skipped')
            return
        for attempt in range(6):
            try:
                self.tg.call('setWebhook', url=self.settings.base_url + '/telegram',
                             secret_token=self.settings.secret, max_connections=1,
                             allowed_updates=['message', 'callback_query'], drop_pending_updates=False)
                self.registered = True
                LOG.warning('Telegram webhook registered; ready for messages')
                return
            except Exception as error:
                LOG.warning('Webhook registration failed (%s), attempt %d/6', type(error).__name__, attempt + 1)
                if attempt < 5:
                    time.sleep(10)
        LOG.error('Check Telegram token and public HTTPS URL, then redeploy')

    def submit(self, update):
        now = time.monotonic()
        with self.lock:
            while self.seen and (len(self.seen) >= 2048 or now - next(iter(self.seen.values())) > 3600):
                self.seen.popitem(last=False)
            uid = update['update_id']
            if uid in self.seen:
                return True
            try:
                self.jobs.put_nowait(update)
            except queue.Full:
                return False
            self.seen[uid] = now
            return True

    def prune(self):
        now = time.monotonic()
        for key in list(self.pending):
            if self.pending[key]['expires'] <= now:
                del self.pending[key]

    def consume(self):
        while True:
            try:
                update = self.jobs.get(timeout=60)
            except queue.Empty:
                self.prune()
                continue
            try:
                self.process(update)
            finally:
                self.jobs.task_done()

    def process(self, update):
        callback = update.get('callback_query')
        message = callback.get('message', {}) if isinstance(callback, dict) else update.get('message', {})
        chat = None
        try:
            if not isinstance(message, dict) or message.get('chat', {}).get('type') != 'private':
                return
            chat = message['chat']['id']
            sender = callback.get('from', {}) if isinstance(callback, dict) else message.get('from', {})
            user = sender.get('id')
            if type(user) is not int or type(chat) is not int:
                return
            text = message.get('text', '')
            command = text.split(' ', 1)[0].split('@', 1)[0]
            if not callback and command == '/id':
                self.tg.say(chat, f'Your Telegram user ID: {user}\nSet ALLOWED_USER_IDS in Render Environment, then save and redeploy.')
                return
            if not callback and command == '/privacy':
                self.tg.say(chat, PRIVACY)
                return
            if user not in self.settings.allowed:
                self.tg.say(chat, 'Access disabled / មិនទាន់អនុញ្ញាត។ Send /id, then set ALLOWED_USER_IDS in Render Environment and redeploy.')
                return
            self.prune()
            if callback:
                try:
                    self.tg.call('answerCallbackQuery', callback_query_id=callback.get('id'), text='Processing…')
                except Exception:
                    pass  # An old button may outlive Telegram's short acknowledgement window.
                self.handle_callback(chat, user, callback.get('data', ''))
            elif command in ('/start', '/help'):
                self.tg.say(chat, HELP)
            elif command == '/status':
                self.tg.say(chat, 'Bot running — VirusTotal API mode.\nSend /privacy for file-sharing details.\nPrivate use only; 20 MB file limit. Free API quotas apply.')
            elif command == '/hash':
                parts = text.split()
                if len(parts) != 2 or not SHA256.fullmatch(parts[1]):
                    self.tg.say(chat, 'Usage: /hash followed by a 64-character SHA-256 hash.')
                    return
                self.throttle(user)
                digest = parts[1].lower()
                self.tg.say(chat, '🔎 Looking up the hash / កំពុងពិនិត្យ hash…')
                report = self.vt.lookup(digest)
                self.tg.say(chat, report_text(report.get('attributes', {}), digest) if report else
                            '⚠️ Hash not found. No scan performed; safety is unknown.')
            elif message.get('document'):
                self.throttle(user)
                self.handle_document(chat, user, message['document'])
            else:
                self.tg.say(chat, 'Send as File / Document to keep the original bytes. /help /privacy')
        except UserError as error:
            self.safe_say(chat, '⚠️ ' + str(error))
        except Exception as error:
            LOG.warning('Request failed (%s)', type(error).__name__)
            self.safe_say(chat, '⚠️ Request failed. Safety is unknown. Please try again later.')

    def safe_say(self, chat, text):
        if chat is None:
            return
        try:
            self.tg.say(chat, text)
        except Exception as error:
            LOG.warning('Could not send result (%s)', type(error).__name__)

    def throttle(self, user):
        now = time.monotonic()
        if now - self.last_request.get(user, -1000) < 15:
            raise UserError('Please wait 15 seconds between file/hash requests.')
        self.last_request[user] = now

    def handle_document(self, chat, user, document):
        if document.get('file_size', 0) > MAX_BYTES:
            raise UserError('File is too large. Maximum: 20 MB.')
        file_id = document.get('file_id')
        if not isinstance(file_id, str) or not file_id:
            raise UserError('Telegram file is unavailable.')
        self.tg.say(chat, '🔎 Checking SHA-256 / កំពុងពិនិត្យ hash…\nOnly the hash is sent to VirusTotal. File contents stay with Telegram/Render unless you approve an upload.')
        with tempfile.TemporaryDirectory(prefix='tgscan-') as directory:
            digest, size = self.tg.download(file_id, Path(directory) / 'sample.bin')
        # The temporary file is already deleted before querying VirusTotal.
        report = self.vt.lookup(digest)
        if report:
            self.tg.say(chat, report_text(report.get('attributes', {}), digest))
        else:
            self.tg.say(chat, f'⚠️ No existing report / មិនមានរបាយការណ៍។\nNo scan performed; safety is unknown.\nSHA-256: {digest}')
        while len(self.pending) >= 64:
            self.pending.popitem(last=False)
        key = secrets.token_urlsafe(12)
        self.pending[key] = dict(chat=chat, user=user, file_id=file_id, digest=digest,
                                 size=size, expires=time.monotonic() + PENDING_TTL, stage='consent')
        self.tg.say(chat,
                    'Upload this file to VirusTotal for analysis?\n'
                    'By tapping Upload, you agree to send its contents to VirusTotal, where they may be retained and shared with security partners and premium customers. Reports are public. Do not upload confidential files. The bot cannot delete the uploaded copy.\n\n'
                    'ចុច Upload មានន័យថាយល់ព្រមផ្ញើឯកសារទៅ VirusTotal។ ឯកសារអាចត្រូវបានរក្សាទុក និងចែករំលែក។ កុំផ្ញើឯកសារសម្ងាត់។\n'
                    f'SHA-256: {digest}\nBytes: {size}\nConsent expires in 15 minutes.',
                    [[{'text': 'Upload to VirusTotal', 'callback_data': 'upload:' + key}],
                     [{'text': 'Cancel / បោះបង់', 'callback_data': 'cancel:' + key}]])

    def handle_callback(self, chat, user, data):
        if not isinstance(data, str) or ':' not in data:
            return
        action, key = data.split(':', 1)
        item = self.pending.get(key)
        if not item or item['user'] != user or item['chat'] != chat:
            raise UserError('This request expired or belongs to another user. Send the file again for a hash lookup.')
        if action == 'cancel':
            del self.pending[key]
            self.tg.say(chat, 'Pending request cancelled. Copies already submitted to VirusTotal cannot be deleted by this bot.')
        elif action == 'upload' and item['stage'] == 'consent':
            # Consume consent before any I/O, so replayed buttons cannot upload twice.
            item['stage'] = 'submitting'
            self.tg.say(chat, 'Uploading the approved file to VirusTotal / កំពុង Upload…')
            try:
                with tempfile.TemporaryDirectory(prefix='tgscan-') as directory:
                    path = Path(directory) / 'sample.bin'
                    digest, size = self.tg.download(item['file_id'], path)
                    if digest != item['digest'] or size != item['size']:
                        raise UserError('The file no longer matches the consented hash. Upload cancelled.')
                    item['analysis_id'] = self.vt.upload(path)
            except Exception:
                item['stage'] = 'failed'
                self.safe_say(chat, 'Upload did not complete normally. It may already have reached VirusTotal. No automatic retry will occur. Send the file again for a hash lookup.')
                raise
            item['stage'] = 'analysis'
            item['expires'] = time.monotonic() + PENDING_TTL
            self.tg.say(chat, 'File submitted; local copy deleted. Analysis may take a few minutes. Tap Check result after about 30 seconds. No verdict is available yet.',
                        [[{'text': 'Check result / មើលលទ្ធផល', 'callback_data': 'check:' + key}]])
        elif action == 'check' and item['stage'] == 'analysis':
            now = time.monotonic()
            if now - item.get('last_check', -1000) < 30:
                raise UserError('Please wait 30 seconds before checking this analysis again.')
            item['last_check'] = now
            result = self.vt.analysis(item['analysis_id'])
            attrs = result.get('attributes', {})
            if attrs.get('status') in ('queued', 'in-progress'):
                self.tg.say(chat, '⏳ VirusTotal is still analysing. Tap Check result again in 30 seconds.',
                            [[{'text': 'Check result', 'callback_data': 'check:' + key}]])
            elif attrs.get('status') == 'completed':
                self.tg.say(chat, report_text(attrs, item['digest'], fresh=True))
                del self.pending[key]
            else:
                raise UserError('Analysis status is unknown. Try the hash later.')
        else:
            raise UserError('This button has already been used. Use Check result or send the file again for a hash lookup.')


if __name__ == '__main__':
    # Existing Render services may still use `python bot.py` as their start command.
    # Replace this process with Gunicorn so it receives Render's shutdown signals.
    import sys

    root = Path(__file__).resolve().parent
    os.execv(sys.executable, [
        sys.executable, '-m', 'gunicorn', '--chdir', str(root),
        '-c', str(root / 'gunicorn.conf.py'), 'app:app',
    ])
