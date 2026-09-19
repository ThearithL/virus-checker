"""HTTP entry point. Importing this module never sends network requests."""
import hmac
import os

from flask import Flask, jsonify, request
from bot import Checker, Settings


def create_app(checker):
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 128 * 1024
    app.config['CHECKER'] = checker

    @app.get('/')
    @app.get('/health')
    def health():
        return jsonify(status='ok', service='Telegram Virus Checker',
                       webhook='registered' if checker.registered else 'pending')

    @app.post('/telegram')
    def webhook():
        received = request.headers.get('X-Telegram-Bot-Api-Secret-Token', '')
        if not hmac.compare_digest(received.encode(), checker.settings.secret.encode()):
            return jsonify(error='unauthorized'), 403
        update = request.get_json(silent=True)
        if not isinstance(update, dict) or type(update.get('update_id')) is not int:
            return jsonify(error='invalid update'), 400
        if not checker.submit(update):
            # Telegram retries non-2xx deliveries instead of silently losing a job.
            return jsonify(error='queue full; retry'), 503
        return jsonify(ok=True)

    return app


app = create_app(Checker(Settings.from_env()))

if __name__ == '__main__':
    # Local development only. Render uses gunicorn.conf.py.
    app.config['CHECKER'].start()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', '10000')), threaded=True)
