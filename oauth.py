#!/usr/bin/env python

#
# OAuth a google account so that
# we can "listen" for new emails / send replies.
#

import google.oauth2.credentials
import google_auth_oauthlib.flow

from flask import Flask, redirect, request, g, url_for

try:
    import simplejson as json
except:
    import json

from .config import Config


SCOPES = [
    'https://mail.google.com/'
]

app = Flask(__name__)


def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()


def credentials_to_dict(credentials):
    return {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
    }


@app.route('/', methods=['GET'])
def oauth_init():
    # Use the client_secret.json file to identify the application requesting
    # authorization. The client ID (from that file) and access scopes are required.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            Config.CLIENT_SECRETS_FILE,
            scopes=SCOPES)

    # Indicate where the API server will redirect the user after the user completes
    # the authorization flow. The redirect URI is required. The value must exactly
    # match one of the authorized redirect URIs for the OAuth 2.0 client, which you
    # configured in the API Console. If this value doesn't match an authorized URI,
    # you will get a 'redirect_uri_mismatch' error.
    flow.redirect_uri = url_for('oauth_callback', _external=True)

    # Generate URL for request to Google's OAuth 2.0 server.
    # Use kwargs to set optional request parameters.
    authorization_url, state = flow.authorization_url(
            # Enable offline access so that you can refresh an access token without
            # re-prompting the user for permission. Recommended for web server apps.
            access_type='offline',
            # Enable incremental authorization. Recommended as a best practice.
            include_granted_scopes='true')

    g.state = state

    return redirect(authorization_url)


@app.route('/oauth', methods=['GET'])
def oauth_callback():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            Config.CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            state=g.get('state'))
    flow.redirect_uri = url_for('oauth_callback', _external=True)

    flow.fetch_token(authorization_response=request.url)

    with open(Config.USER_SECRETS_FILE, 'w+') as secrets:
        json.dump(credentials_to_dict(flow.credentials), secrets)

    return redirect(url_for('shutdown'))


@app.route('/shutdown', methods=['GET'])
def shutdown():
    shutdown_server()
    return 'shutting down...'


def run_app():
    import os
    os.environ['DEBUG'] = '1'
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run(port=5001)


if __name__ == '__main__':
    from threading import Thread
    from selenium import webdriver

    app_thread = Thread(target=run_app)
    app_thread.start()

    from time import sleep
    sleep(1)

    driver = None
    try:
        driver = webdriver.Chrome()
        driver.get('http://localhost:5001/')

        app_thread.join()
    finally:
        if driver is not None:
            driver.close()

