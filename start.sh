#!/bin/sh
set -eu
# Fail startup if initial definitions cannot be fetched/updated.
freshclam --stdout
freshclam --daemon --stdout &
exec python3 -u /app/bot.py
