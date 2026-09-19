import os

bind = '0.0.0.0:' + os.environ.get('PORT', '10000')
workers = 1  # Queue, consent records and API rate limiter belong to this process.
worker_class = 'gthread'
threads = 4
timeout = 120
graceful_timeout = 30
accesslog = '-'
errorlog = '-'
preload_app = False


def post_worker_init(worker):
    # Start threads after fork, including when Render sets --preload by default.
    worker.wsgi.config['CHECKER'].start()
