#!/usr/bin/env python

from flask import Flask, request
from flask_restful import Resource, Api
import googleapiclient.discovery
import google.oauth2.credentials
from email.mime.text import MIMEText
import base64
import uuid

try:
    import simplejson as json
except:
    import json

from .config import Config


app = Flask(__name__)
api = Api(app)

ACCOUNTS = {
        Config.USER_EMAIL: {
            'id': Config.USER_EMAIL,
            'credentials_path': Config.USER_SECRETS_FILE
        }
}

EMAIL_DOMAIN = Config.USER_EMAIL.split('@')[-1]


def read_subject(message):
    return read_header(message, 'Subject')


def read_message_id(message):
    return read_header(message, 'Message-ID')


def read_header(message, header):
    for h in message['payload']['headers']:
        if h['name'] == header:
            return h['value']
    return None


def email_id():
    return '<{}@{}>'.format(uuid.uuid4().hex.upper(), EMAIL_DOMAIN)


class Index(Resource):
    def get(self):
        return {'status': 'ok'}, 200

    def post(self):
        """

        """
        content = request.get_json()
        if content['as'] not in ACCOUNTS:
            return {'status': 'error', 'as': 'Invalid profile. Cannot post as %s'.format(content['as']['profile_id'])}, 400

        with open(ACCOUNTS[content['as']]['credentials_path']) as f:
            credentials = google.oauth2.credentials.Credentials(**json.load(f))

        client = googleapiclient.discovery.build('gmail', 'v1', credentials=credentials)\
            .users()\
            .messages()

        message_id, thread_id = content['activity']['in_reply_to'].split(':')

        message = client.get(userId='me', id=message_id).execute()

        reply = MIMEText(content['activity']['text'])
        reply['To'] = read_header(message, 'From')
        reply['From'] = read_header(message, 'To')
        reply['Subject'] = read_subject(message)
        reply['Message-ID'] = email_id()
        reply['References'] = read_header(message, 'Message-ID')
        reply['In-Reply-To'] = read_header(message, 'Message-ID')

        raw = base64.urlsafe_b64encode(reply.as_string().encode('utf-8')).decode('utf-8')

        response = client.send(userId='me', body={'raw': raw, 'threadId': thread_id})\
            .execute()
        return {
            'status': 'ok',
            'activity': {
                'activity_id': '{}:{}'.format(response['id'], thread_id)
            }
        }, 200


api.add_resource(Index, '/')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
