import os
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())


class Config(object):
    DEBUG = os.environ['DEBUG']
    LOCAL = os.environ['LOCAL']
    CLIENT_SECRETS_FILE = os.environ['CLIENT_SECRETS_FILE']
    USER_SECRETS_FILE = os.environ['USER_SECRETS_FILE']
    USER_EMAIL = os.environ['USER_EMAIL']
    AUTH_SCOPE = os.environ['AUTH_SCOPE']
    API_KEY = os.environ['API_KEY']
    DRIVER_ID = os.environ['DRIVER_ID']
    SIGNATURE_METHOD = os.environ['SIGNATURE_METHOD']
    SIGNATURE_KEY = os.environ['SIGNATURE_KEY']
    NETWORK_ID = int(os.environ['NETWORK_ID'])
    NETWORK_NAME = os.environ['NETWORK_NAME']
