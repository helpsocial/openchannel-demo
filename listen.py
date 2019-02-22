#!/usr/bin/env python

"""
Polls GMAIL for new message every 60s
and submits the messages to the OpenChannel
inbound webhook configured for the driver
application.
/open_channel/<app_id>
/open_channel/<app_id>
"""

import base64
import googleapiclient.discovery
import google.oauth2.credentials
import hashlib
import hmac
import os
import re
import requests
import sys

try:
    import simlejson as json
except ImportError as e:
    import json

from argparse import ArgumentParser
from datetime import datetime, timezone
from time import sleep, time

from .config import Config


def parse_timestamp(timestamp):
    """

    :param str|int timestamp:
    :return:
    """
    micro = int(timestamp) % 1000
    dt = datetime.fromtimestamp(int(timestamp) / 1000)
    return dt.replace(microsecond=micro).replace(tzinfo=timezone.utc).isoformat()


def parse_addressline(address):
    """

    :param str address:
    :return:
    """
    pattern = re.compile('^(?P<name>[^<]+)?[<](?P<email>[^>]+)[>]$')
    matcher = pattern.match(address)
    if matcher is None:
        return None, address.strip()
    name = matcher.group('name')
    if name is not None:
        name = name.strip()
    return name, matcher.group('email')


def get_formatted_id(message):
    return '{}:{}'.format(message['id'], message['threadId'])


def swap_url_safe_character_mapping(s):
    """
    Swap the default python urlsafe base64 character mapping
    for the character mapping used by HelpSocial api.

    :param s:
    :return:
    """
    decoded = base64.urlsafe_b64decode(s.encode('utf-8'))
    return base64.b64encode(decoded).translate(bytes.maketrans(b'=/+', b'_-.'))


def get_attachment(users_service, message_id, attachment_id):
    """

    :param googleapiclient.discovery.Resource users_service:
    :param str message_id:
    :param str attachment_id:
    :return:
    """
    attachment = users_service.messages()\
        .attachments()\
        .get(userId='me', messageId=message_id, id=attachment_id)\
        .execute()
    return swap_url_safe_character_mapping(attachment['data']), attachment['size']


def to_attachment(users_service, message_id, data):
    """

    :param googleapiclient.discovery.Resource users_service:
    :param str message_id:
    :param dict data:
    :return:
    """
    raw, size = get_attachment(users_service, message_id, data['body']['attachmentId'])
    return {
        'type': 'file',
        'raw_data': raw,
        'meta': {
            'filename': '.'.join(data['filename'].split('.')[:-1]),
            'extension': data['filename'].split('.')[-1],
            'size': size,
            'mime': data['mimeType'],
            'attachment_id': data['body']['attachmentId'],
        }
    }


def get_message_parent(users_service, thread_id, message_id):
    """

    :param googleapiclient.discovery.Resource users_service:
    :param thread_id:
    :param message_id:
    :return:
    """
    thread = users_service.threads().get(userId='me', id=thread_id).execute()
    messages = sorted(thread['messages'],
                      key=lambda t: t['internalDate'],
                      reverse=True)
    previous = None
    for message in messages:
        if message['id'] == message_id:
            return previous
        previous = message
    return None


def to_activity_create_callback(users_service, message):
    """
    Format GMail message into HelpSocial activity
    for OpenChannel.

    :param googleapiclient.discovery.Resource users_service:
    :param dict message:
    :return:
    """
    data = {
        'activity_id': get_formatted_id(message),
        'type_id': 10,
        'network': {
            'id': Config.NETWORK_ID
        },
        'posted_at': parse_timestamp(message['internalDate']),
        'meta': {
            'label_ids': message['labelIds'],
            'history_id': message['historyId'],
        }
    }

    parent = get_message_parent(users_service, message['threadId'], message['id'])
    if parent is not None:
        data['in_reply_to'] = get_formatted_id(parent)

    posted_by = {
        'profile_id': '',
        'username': ''
    }
    sent_to = {
        'profile_id': '',
        'username': ''
    }

    headers = []

    for header in message['payload']['headers']:
        if 'Delivered-To' == header['name']:
            display_name, email = parse_addressline(header['value'])
            if not sent_to['profile_id'] and email:
                sent_to['profile_id'] = sent_to['username'] = email
            if display_name and 'display_name' not in sent_to:
                sent_to['display_name'] = display_name
        elif 'To' == header['name']:
            display_name, email = parse_addressline(header['value'])
            if not sent_to['profile_id'] and email:
                sent_to['profile_id'] = sent_to['username'] = email
            if display_name and 'display_name' not in sent_to:
                sent_to['display_name'] = display_name
        elif 'From' == header['name']:
            display_name, email = parse_addressline(header['value'])
            if not posted_by['profile_id'] and email:
                posted_by['profile_id'] = posted_by['username'] = email
            if display_name and 'display_name' not in posted_by:
                posted_by['display_name'] = display_name
        elif 'Subject' == header['name']:
            data['meta']['subject'] = header['value']
        else:
            headers.append(header)

    data['meta']['headers'] = headers
    data['sent_to'] = sent_to
    data['posted_by'] = posted_by

    def parse_payload_part(part):
        if 'parts' in part:
            for p in part['parts']:
                parse_payload_part(p)
        elif 'text/plain' == part['mimeType']:
            data['text'] = base64.urlsafe_b64decode(part['body']['data'].encode()).decode()
        elif 'text/html' == part['mimeType']:
            data['meta']['html_text'] = base64.urlsafe_b64decode(part['body']['data'].encode()).decode()
        else:
            if 'attachments' not in data:
                data['attachments'] = []
            data['attachments'].append(to_attachment(users_service, message['id'], part))

    for part in message['payload']['parts']:
        parse_payload_part(part)

    # prefix text with [SUBJECT]:
    data['text'] = '[{}]: {}'.format(data['meta']['subject'], data['text'])

    return {
        'object': 'activity',
        'action': 'create',
        'timestamp': int(datetime.now().replace(tzinfo=timezone.utc).timestamp()),
        'data': data
    }


def queue(url, callback):
    """

    :param str url:
    :param dict callback:
    :return:
    """
    print('Queueing {}'.format(json.dumps(callback)))
    body = json.dumps(callback)
    signature = hmac.new(
        Config.SIGNATURE_KEY.encode('utf-8'),
        body.encode('utf-8'),
        digestmod=hashlib.sha256).hexdigest()
    headers = {
        'content-type': 'application/vnd.helpsocial.openchannel+json',
        'x-auth-scope': Config.AUTH_SCOPE,
        'x-api-key': Config.API_KEY,
        'x-openchannel-signature': signature
    }
    response = requests.post(url, data=body, headers=headers, verify=False)
    print(response.json())
    return 200 == response.status_code


def history_poll(users_service, history_id=None):
    print('Polling for new messages.')
    kwargs = {
        'userId': 'me',
        'historyTypes': 'messagesAdded',
        'startHistoryId': history_id,
        'labelId': 'INBOX'
    }
    history = users_service.history().list(**kwargs).execute()
    changes = history['history'] if 'history' in history else []
    while 'nextPageToken' in history:
        kwargs['pageToken'] = history['nextPageToken']
        history = users_service.history().list(**kwargs).execute()
        changes.extend(history['history'])
    messages = []
    for change in changes:
        messages.extend(change['messagesAdded'] if 'messagesAdded' in change else [])
    for item in sorted(messages, key=lambda m: m['internalDate']):
        if 'UNREAD' not in item['labelIds']:
            continue
        yield item


def poll(users_service, last_poll=None):
    """
    Poll GMAIL for new messages

    :param googleapiclient.discovery.Resource users_service:
    :param int|None last_poll:
    :return:
    """
    print('Polling for new messages.')
    criteria = [
        # individual gmail queries such as
        # from:foobar@some.domain
    ]
    if last_poll is not None:
        dt = datetime.fromtimestamp(last_poll)
        criteria.append('after:{}/{}/{}'.format(dt.year, dt.month, dt.day))
    messages = users_service.messages()\
        .list(userId='me',
              labelIds=['INBOX','UNREAD'], q=' '.join(criteria))\
        .execute()
    if 'messages' not in messages:
        print('No new messages.')
        return
    for msg in messages['messages']:
        print('Received {}'.format(msg['id']))
        activity = to_activity_create_callback(
            users_service,
            users_service.messages().get(userId='me', id=msg['id']).execute()
        )
        users_service.messages()\
            .modify(userId='me',
                    id=msg['id'], body={'removeLabelIds': ['UNREAD']})\
            .execute()
        yield activity


def get_webhooks_url(driver_id):
    if Config.LOCAL:
        return 'https://webhooks.helpsocial.test/open_channel/{}'.format(driver_id)
    return 'https://webhooks.helpsocial.me/open_channel/{}'.format(driver_id)


def listen(driver_id, interval=60, keep_alive=-1, webhooks_url=None):
    """

    :param str driver_id:
    :param int interval:
    :param int keep_alive:
    :param str webhooks_url:
    :return:
    """
    if webhooks_url is None:
        webhooks_url = get_webhooks_url(driver_id)
    if not os.path.exists(Config.USER_SECRETS_FILE):
        print('Credential [{}] not found.'.format(Config.USER_SECRETS_FILE))
        sys.exit(1)
    if interval < 60 or interval > 300:
        print('Invalid interval. Value must be between 60 and 300 seconds (5 minutes).')
        sys.exit(1)

    with open(Config.USER_SECRETS_FILE) as creds:
        credentials = google.oauth2.credentials.Credentials(**json.load(creds))

    users_service = googleapiclient.discovery.build('gmail', 'v1', credentials=credentials)\
        .users()

    print('Starting listen loop.')
    forever = keep_alive < 0
    start = time()
    last_poll = None
    history_id = None
    while forever or (time() < (start + keep_alive)):
        if last_poll is None or (time() - last_poll) >= 60:
            first = True
            last_poll = time()
            if history_id is None:
                for message in poll(users_service):
                    history_id = message['historyId'] if first else history_id
                    queue(webhooks_url, message)
                    first = False
            else:
                for message in history_poll(users_service, history_id):
                    history_id = message['historyId'] if first else history_id
                    queue(webhooks_url, message)
                    first = False
        if not forever and keep_alive < interval:
            break
        sleep(interval)
    print('Exiting listen loop.')


parser = ArgumentParser()
parser.add_argument('--interval', default=60)
parser.add_argument('--keep-alive', default=-1)
parser.add_argument('--webhook', dest='webhooks_url')


if __name__ == '__main__':
    kwargs = vars(parser.parse_args())
    listen(Config.DRIVER_ID, **kwargs)

