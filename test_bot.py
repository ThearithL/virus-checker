import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import bot

class ScannerTests(unittest.TestCase):
    def result(self, code, output=''):
        with patch('bot.subprocess.run', return_value=subprocess.CompletedProcess([], code, output, '')):
            return bot.scan('/tmp/sample.bin')

    def test_verdicts(self):
        self.assertIn('No threats detected', self.result(0))
        self.assertIn('Threat or suspicious', self.result(1, '/tmp/sample.bin: Test.Signature FOUND\n'))
        self.assertIn('Incomplete scan', self.result(1, 'sample: Heuristics.Encrypted.Zip FOUND\n'))
        self.assertIn('Incomplete scan', self.result(1, 'sample: Heuristics.Limits.Exceeded.MaxScanSize FOUND\n'))
        self.assertIn('Scanner error', self.result(2))
        self.assertNotIn('No threats detected', self.result(1))

    def test_timeout(self):
        with patch('bot.subprocess.run', side_effect=subprocess.TimeoutExpired('clamscan', 120)):
            self.assertIn('Safety is unknown', bot.scan('/tmp/sample.bin'))

    def test_download_enforces_actual_size(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch('bot.MAX_BYTES', 8), patch('bot.urllib.request.urlopen', return_value=io.BytesIO(b'123456789')):
                with self.assertRaises(bot.TooLarge):
                    bot.download('https://example.invalid', Path(folder) / 'sample')

    def test_no_allowlist_denies_scan(self):
        with patch.dict(os.environ, {'TELEGRAM_BOT_TOKEN': 'test', 'ALLOWED_USER_IDS': ''}):
            app = bot.Bot()
        with patch.object(app, 'say') as say, patch('bot.download') as download:
            app.handle({'chat': {'id': 1, 'type': 'private'}, 'from': {'id': 1}, 'document': {'file_id': 'x'}})
            download.assert_not_called()
            self.assertIn('Access disabled', say.call_args.args[1])

    def test_temp_cleanup_on_scan_failure(self):
        with patch.dict(os.environ, {'TELEGRAM_BOT_TOKEN': 'test', 'ALLOWED_USER_IDS': '1'}):
            app = bot.Bot()
        saved = []
        def fake_download(url, path):
            saved.append(path)
            path.write_bytes(b'hello')
            return 5, 'dummy'
        with patch.object(app, 'say'), patch.object(app, 'api', return_value={'file_path': 'x'}), patch('bot.download', side_effect=fake_download), patch('bot.scan', side_effect=RuntimeError()):
            app.handle({'chat': {'id': 1, 'type': 'private'}, 'from': {'id': 1}, 'document': {'file_id': 'x'}})
        self.assertFalse(saved[0].exists())

if __name__ == '__main__':
    unittest.main()
