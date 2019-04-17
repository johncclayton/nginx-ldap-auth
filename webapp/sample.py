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

    def do_GET(self):

        url = urlparse(self.path)
        query_components = parse_qs(url.query)

        if url.path.startswith("/login/relay.html"):
            return self.relay_page(query_components)

        if url.path.startswith("/login"):
            return self.auth_form()

        self.send_response(200)
        self.end_headers()

        self.wfile.write('Hello, world! Requested URL: ' + self.path + '\n')


    def relay_page(self, qc):
        self.log_message("relay query params: %s" % qc)

        html="""
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
  <head>
    <meta http-equiv=Content-Type content="text/html;charset=UTF-8">
    <script src="https://d1813.dyndns.org:5001/webman/sso/synoSSO-1.0.0.js"></script>
    <title>DSM Authenticator - Relay</title>
  </head>
  <body>
    <h1>Syno SSO Relay</h1>
    Access Token: TOKEN
  </body>
  </html>
  """

        self.send_response(200)
        self.end_headers()
        self.wfile.write(html.replace("TOKEN", qc["access_token"]))

        self.log_message("relay.html served")


    # send login form html
    def auth_form(self, target = None):
        # try to get target location from header
        if target == None:
            target = self.headers.get('X-Target')

        # form cannot be generated if target is unknown
        if target == None:
            self.log_error('target url is not passed')
            self.send_response(500)
            return

        html="""
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
  <head>
    <meta http-equiv=Content-Type content="text/html;charset=UTF-8">
    <script src="https://d1813.dyndns.org:5001/webman/sso/synoSSO-1.0.0.js"></script>
    <title>DSM Authenticator</title>
  </head>
  <body>

  <script>
   function setButton (logged) {
      if (logged) {
         document.getElementById('button').innerHTML = '<button onclick="SYNOSSO.logout()">Logout</button>';
      } else {
         document.getElementById('button').innerHTML = '<button onclick="SYNOSSO.login()">Login</button>';
      }
   }
   /** Callback for SSO.
   * Called by init() and login()
   * @param reponse the JSON returned by SSO. See Syno SSO Dev Guide.
   */
   function authCallback(reponse) {
      console.log(JSON.stringify(reponse));
      if (reponse.status == 'login') {
         console.log('logged');
         setButton(true);
      }
      else {
         console.log('not logged ' + reponse.status);
         setButton(false);
      }
   }
   SYNOSSO.init({
      oauthserver_url: 'https://d1813.dyndns.org:5001',
      app_id: '5d125d33ff6e54f6675f8c3b6b6ffc61',
      redirect_uri: 'https://test.d1813.dyndns.org/login/relay.html',
      ldap_baseDN: 'dc=d1813,dc=dyndns,dc=org',
      callback: authCallback
   });
</script>

<h1> Syno SSO test</h1>

<p id='button'></p>

<!--
    <form action="/login" method="post">
      <table>
        <tr>
          <td>Username: <input type="text" name="username"/></td>
        <tr>
          <td>Password: <input type="password" name="password"/></td>
        <tr>
          <td><input type="submit" value="Login"></td>
      </table>
        <input type="hidden" name="target" value="TARGET">
    </form>
-->

  </body>
</html>"""

        self.send_response(200)
        self.end_headers()
        self.wfile.write(html.replace('TARGET', target))


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

        cipher_suite = Fernet(derive_fernet_key())
        enc_data = cipher_suite.encrypt(user + ':' + passwd)

        if user != None and passwd != None and target != None:

            # form is filled, set the cookie and redirect to target
            # so that auth daemon will be able to use information from cookie
            self.send_response(302)

            self.log_message("token value: %s" % enc_data)
            self.send_header('Set-Cookie', 'nginxauth=' + enc_data + '; httponly')

            self.send_header('Location', target)
            self.end_headers()

            return

        self.log_error('some form fields are not provided')
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
