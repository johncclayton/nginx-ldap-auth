#!/bin/sh 
''''which python2 >/dev/null && exec python2 "$0" "$@" # ''' 
''''which python  >/dev/null && exec python  "$0" "$@" # '''

# Copyright (C) 2014-2015 Nginx, Inc.

# Example of an application working on port 9000
# To interact with nginx-ldap-auth-daemon this application
# 1) accepts GET  requests on /login and responds with a login form
# 2) accepts POST requests on /login, sets a cookie, and responds with redirect

import sys, os, signal, base64, Cookie, cgi
from urlparse import urlparse, parse_qs
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def derive_fernet_key():
    password = os.getenv("CRYPTO_PASSWORD", "s77sg2j34kj")
    salt = os.getenv("RANDOM16", "1234567890123456")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())  
    key = kdf.derive(password)
    return base64.urlsafe_b64encode(key)

Listen = ('0.0.0.0', 9000)

import threading
from SocketServer import ThreadingMixIn
class AuthHTTPServer(ThreadingMixIn, HTTPServer):
    pass

class AppHandler(BaseHTTPRequestHandler):
    def encode_cookie(self, cleartext):
        cipher_suite = Fernet(derive_fernet_key())
        enc_data = cipher_suite.encrypt(cleartext)
        return enc_data

    # processes posted form and sets the cookie with login/password
    def do_POST(self):

        # prepare arguments for cgi module to read posted form
        env = {'REQUEST_METHOD':'POST',
               'CONTENT_TYPE': self.headers['Content-Type'],}

        # read the form contents
        form = cgi.FieldStorage(fp = self.rfile, 
                headers = self.headers, environ = env)

        # extract required fields
        user = form.getvalue('username')
        passwd = form.getvalue('password')
        target = form.getvalue('target')

        enc_data = encode_cookie(user + ':' + passwd)
        if user != None and passwd != None and target != None:
            # form is filled, set the cookie and redirect to target
            # so that auth daemon will be able to use information from cookie
            self.send_response(302)
            self.send_header('Set-Cookie', 'nginxauth=' + enc_data + '; httponly')
            self.send_header('Location', target)
            self.end_headers()

            return

        self.auth_form(target)

    def log_message(self, format, *args):
        if len(self.client_address) > 0:
            addr = BaseHTTPRequestHandler.address_string(self)
        else:
            addr = "-"

        sys.stdout.write("%s - - [%s] %s\n" % (addr,
                         self.log_date_time_string(), format % args))

    def log_error(self, format, *args):
        self.log_message(format, *args)


def exit_handler(signal, frame):
    sys.exit(0)

if __name__ == '__main__':
    server = AuthHTTPServer(Listen, AppHandler)
    signal.signal(signal.SIGINT, exit_handler)
    sys.stdout.write("Waiting for /login requests on port 9000")
    sys.stdout.flush()
    server.serve_forever()
