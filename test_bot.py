"""Offline tests: no real Telegram messages or VirusTotal uploads."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault('TELEGRAM_BOT_TOKEN', '123456:offline-test-token')
os.environ.setdefault('VIRUSTOTAL_API_KEY', 'offline-test-key')
os.environ.setdefault('WEBHOOK_SECRET', 'offline-test-secret-that-is-over-32-characters')

import bot
from app import create_app


def settings(allowed=(1, 2)):
    return bot.Settings('123456:offline-test-token', 'offline-test-key',
                        frozenset(allowed), 'offline-test-secret-that-is-over-32-characters', '')


class CheckerTests(unittest.TestCase):
    def setUp(self):
        self.checker = bot.Checker(settings())
        self.checker.tg = Mock()
        self.checker.vt = Mock()
        self.checker.vt.lookup.return_value = None
        self.checker.vt.upload.return_value = 'analysis-id'
        self.paths = []
        self.payload = b'harmless test document'
        self.digest = hashlib.sha256(self.payload).hexdigest()

        def download(file_id, path):
            self.paths.append(path)
            path.write_bytes(self.payload)
            return self.digest, len(self.payload)

        self.checker.tg.download.side_effect = download

    def document(self, user=1, size=10, chat_type='private'):
        return {'update_id': 1, 'message': {
            'chat': {'id': user, 'type': chat_type}, 'from': {'id': user},
            'document': {'file_id': 'test-file', 'file_size': size, 'file_name': '../../bad.exe'}}}

    def callback(self, key, action='upload', user=1):
        return {'update_id': 2, 'callback_query': {
            'id': 'callback', 'from': {'id': user}, 'data': action + ':' + key,
            'message': {'chat': {'id': user, 'type': 'private'}}}}

    def create_consent(self):
        self.checker.process(self.document())
        return next(iter(self.checker.pending))

    def output(self):
        return '\n'.join(call.args[1] for call in self.checker.tg.say.call_args_list)

    def test_unknown_hash_never_uploads_without_consent_and_deletes_temp_file(self):
        self.create_consent()
        self.checker.vt.lookup.assert_called_once_with(self.digest)
        self.checker.vt.upload.assert_not_called()
        self.assertIn('safety is unknown', self.output().lower())
        self.assertIn('retained and shared', self.output())
        self.assertTrue(self.paths)
        self.assertTrue(all(not path.exists() for path in self.paths))

    def test_known_report_is_labelled_existing_and_still_needs_consent(self):
        self.checker.vt.lookup.return_value = {'attributes': {'last_analysis_stats': {'undetected': 3}}}
        self.create_consent()
        self.assertIn('Existing report — not a new scan', self.output())
        self.checker.vt.upload.assert_not_called()

    def test_empty_allowlist_and_group_chats_do_not_scan(self):
        self.checker.settings = settings(())
        self.checker.process(self.document())
        self.checker.process(self.document(chat_type='group'))
        self.checker.tg.download.assert_not_called()
        self.checker.vt.lookup.assert_not_called()

    def test_id_works_before_user_is_allowed(self):
        self.checker.settings = settings(())
        update = self.document()
        update['message'] = {'chat': {'id': 1, 'type': 'private'}, 'from': {'id': 1}, 'text': '/id'}
        self.checker.process(update)
        self.assertIn('user ID: 1', self.output())

    def test_other_allowed_user_cannot_consume_consent(self):
        key = self.create_consent()
        self.checker.process(self.callback(key, user=2))
        self.checker.vt.upload.assert_not_called()
        self.assertEqual(self.checker.pending[key]['stage'], 'consent')

    def test_expired_and_cancelled_consent_cannot_upload(self):
        key = self.create_consent()
        self.checker.pending[key]['expires'] = 0
        self.checker.process(self.callback(key))
        self.checker.vt.upload.assert_not_called()
        self.checker.last_request.clear()
        key = self.create_consent()
        self.checker.process(self.callback(key, action='cancel'))
        self.checker.process(self.callback(key))
        self.checker.vt.upload.assert_not_called()

    def test_upload_requires_same_hash_and_is_one_time(self):
        key = self.create_consent()
        self.checker.process(self.callback(key))
        self.checker.process(self.callback(key))
        self.checker.vt.upload.assert_called_once()
        self.assertTrue(all(not path.exists() for path in self.paths))
        self.assertEqual(self.checker.pending[key]['stage'], 'analysis')

    def test_changed_file_is_not_uploaded(self):
        key = self.create_consent()
        self.digest = 'f' * 64
        self.checker.process(self.callback(key))
        self.checker.vt.upload.assert_not_called()
        self.assertIn('no longer matches', self.output())

    def test_upload_error_cleans_file_and_does_not_retry(self):
        key = self.create_consent()
        self.checker.vt.upload.side_effect = RuntimeError('secret-url-do-not-log')
        self.checker.process(self.callback(key))
        self.checker.process(self.callback(key))
        self.checker.vt.upload.assert_called_once()
        self.assertTrue(all(not path.exists() for path in self.paths))
        self.assertNotIn('secret-url-do-not-log', self.output())

    def test_advertised_size_limit_prevents_download(self):
        self.checker.process(self.document(size=bot.MAX_BYTES + 1))
        self.checker.tg.download.assert_not_called()
        self.checker.vt.lookup.assert_not_called()

    def test_queued_analysis_is_not_a_clean_verdict(self):
        key = self.create_consent()
        self.checker.process(self.callback(key))
        self.checker.tg.say.reset_mock()
        self.checker.vt.analysis.return_value = {'attributes': {'status': 'queued', 'stats': {}}}
        self.checker.process(self.callback(key, action='check'))
        self.assertIn('still analysing', self.output())
        self.assertNotIn('No detections', self.output())
        self.assertIn(key, self.checker.pending)

    def test_completed_analysis_reports_detection(self):
        key = self.create_consent()
        self.checker.process(self.callback(key))
        self.checker.vt.analysis.return_value = {'attributes': {
            'status': 'completed', 'stats': {'malicious': 2, 'undetected': 8}}}
        self.checker.process(self.callback(key, action='check'))
        self.assertIn('Malicious: 2', self.output())
        self.assertNotIn(key, self.checker.pending)


class NetworkBoundaryTests(unittest.TestCase):
    def test_download_checks_actual_stream_size(self):
        client = bot.Telegram('offline-test')
        response = Mock(status_code=200)
        response.iter_content.return_value = [b'123', b'456']
        context = Mock()
        context.__enter__ = Mock(return_value=response)
        context.__exit__ = Mock(return_value=False)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(client, 'call', return_value={'file_path': 'documents/file'}), \
                    patch('bot.requests.get', return_value=context), patch('bot.MAX_BYTES', 5):
                with self.assertRaises(bot.UserError):
                    client.download('file', Path(directory) / 'sample.bin')

    def test_quota_is_not_a_missing_or_clean_report(self):
        client = bot.VirusTotal('offline-test-key')
        response = Mock(status_code=429, headers={'Retry-After': '120'})
        context = Mock()
        context.__enter__ = Mock(return_value=response)
        context.__exit__ = Mock(return_value=False)
        with patch('bot.requests.request', return_value=context) as request:
            with self.assertRaises(bot.UserError):
                client.lookup('a' * 64)
            with self.assertRaises(bot.UserError):
                client.lookup('a' * 64)
            request.assert_called_once()

    def test_no_engine_results_and_incomplete_coverage(self):
        text = bot.report_text({'last_analysis_stats': {}}, 'a' * 64)
        self.assertIn('No usable engine results', text)
        self.assertNotIn('No detections in returned', text)
        text = bot.report_text({'last_analysis_stats': {'undetected': 2, 'failure': 1}}, 'a' * 64)
        self.assertIn('Coverage is incomplete', text)
        self.assertIn('does not guarantee safety', text)


class WebhookTests(unittest.TestCase):
    def setUp(self):
        self.checker = bot.Checker(settings())
        self.client = create_app(self.checker).test_client()
        self.headers = {'X-Telegram-Bot-Api-Secret-Token': self.checker.settings.secret}

    def test_health_has_no_credentials(self):
        response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(self.checker.settings.token, response.text)
        self.assertNotIn(self.checker.settings.vt_key, response.text)

    def test_invalid_webhook_secret_rejected_before_queue(self):
        response = self.client.post('/telegram', json={'update_id': 1})
        self.assertEqual(response.status_code, 403)
        self.assertTrue(self.checker.jobs.empty())

    def test_duplicate_deliveries_are_accepted_without_duplicate_job(self):
        for _ in range(2):
            response = self.client.post('/telegram', json={'update_id': 1}, headers=self.headers)
            self.assertEqual(response.status_code, 200)
        self.assertEqual(self.checker.jobs.qsize(), 1)

    def test_queue_full_asks_telegram_to_retry_and_retry_can_succeed(self):
        for update_id in range(4):
            self.client.post('/telegram', json={'update_id': update_id}, headers=self.headers)
        response = self.client.post('/telegram', json={'update_id': 5}, headers=self.headers)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(5, self.checker.seen)
        self.checker.jobs.get_nowait()
        response = self.client.post('/telegram', json={'update_id': 5}, headers=self.headers)
        self.assertEqual(response.status_code, 200)

    def test_malformed_update_and_large_request_rejected(self):
        response = self.client.post('/telegram', json={'update_id': 'bad'}, headers=self.headers)
        self.assertEqual(response.status_code, 400)
        response = self.client.post('/telegram', data=b'x' * (128 * 1024 + 1),
                                    content_type='application/json', headers=self.headers)
        self.assertEqual(response.status_code, 413)


if __name__ == '__main__':
    unittest.main()
