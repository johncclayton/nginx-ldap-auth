#!/usr/bin/env sh
set
python -u /code/nginx-ldap-auth-daemon.py --host 0.0.0.0 --port 8888 --cookie "$COOKIE" \
	--realm "$REALM" -b "$BASE" -D "$BIND_DN" -w "$BIND_PASS" --url "$URL" --filter "$FILTER"
