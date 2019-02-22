
# OpenChannel Demo

This demo uses the Gmail API to periodically poll for new messages
to a specific users inbox. These new messages are imported to HelpSocial
using OpenChannel Specification webhooks. The messages can then be replied
to from within HelpSocial using the CallbackDriver.

## Setup

**!! PYTHON 3.6 REQUIRED !!**

**virtual environment manager highly recommended**

Copy the `.env.example` file to `.env`.

The `CLIENT_SECRETS_FILE` is a json file containing your Google API
client credentials. The default value is `.client_secret.json`

The `USER_SECRETS_FILE` is a json file containing the specific user whose
inbox you wish to monitors Google API credentials. The default value is
`.user_secret.json`. This file is automatically populated by running the
`oauth.py` script.


The `USER_EMAIL` is the user's email whose credential is in `USER_SECRETS_FILE`.

The `AUTH_SCOPE` is your HelpSocial auth scope.

In the next steps we will fill out the rest of the required
configuration information.

### Create a new network

```
POST https://api.helpsocial.com/2.0/networks
{
    "name": "gmail"
}
```

Add the returned network id and name to your `.env` as `NETWORK_ID` and
`NETWORK_NAME` respectively.


### Create a Callback Driver

```
POST https://api.helpsocial.com/2.0/drivers
{
    "type": "callback",
    "name": "Gmail OpenChannel Driver",
    "signature": {
        "method": "sha256"
    },
    "actions": [
        {
            "name": "reply",
            "method": "POST",
            "url": "https://127.0.0.1:5000/"
        }
    ]
}
```

Using the response set the remaining `.env` keys.

 
- `data.driver.id` => `DRIVER_ID`
- `data.driver.credential.key` => `API_KEY`
- `data.driver.application.signature.method` => `SIGNATURE_METHOD`
- `data.driver.application.signature.key` => `SIGNATURE_KEY`


## oauth.py

`oauth.py` runs a simple webserver and directs the user through generating
a credentials file to be used with Google's APIs.

## api.py

`api.py` defines the server that powers the HelpSocial API Callback client defined
by the Callback driver created earlier.

In the earlier Callback Driver definition we specify only a single action is
supported, `reply`. The action is triggered by a callback to our local api
at path `/` and method `POST`.

This api is responsible for consuming OpenChannel action callbacks, interpreting
the request, and returning an appropriate response.


## listen.py

`listen.py` runs a listener task which is responsible for polling the Gmail API
at a set interval looking for new messages to be imported. New messages are
passed to HelpSocial through an OpenChannel Specification webhook.

Once the inbound message is fully processed it will be available within
HelpSocial connect and through the HelpSocial API.

The message can be replied to through the HelpSocial API and the Connect dashboard
through the configured Callback driver.
