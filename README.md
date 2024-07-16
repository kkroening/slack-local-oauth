# slack-local-oauth: Perform Slack user OAuth flow from the terminal

This demonstrates an end-to-end Slack OAuth flow to get a *user* access-token from the terminal with no other dependencies besides Python 3.11+ (and optionally OpenSSL).

The script...

1.  runs a local HTTPS OAuth callback server (with a self-signed certificate+key pair generated automatically unless provided)
2.  opens a browser tab to show the Slack OAuth consent screen
3.  handles the OAuth callback and exchanges the auth code for an access token
4.  outputs the access token to stdout

Configuration is done via a `.slack.conf` file in the current working directory, and the access token is cached by updating the config.

> [!WARNING]
> This script scratches a very particular DevOps scripting itch and is not meant to be very general purpose.  It's being shared mainly for the sake of example, since it's not easy to find a self-contained example of the end-to-end OAuth flow.

## Usage

Ensure that `https://localhost:8103` (or whatever port you want) is listed in your Slack app's allowed OAuth redirect URLs.

Write a `.slack.conf` file in the current working directory like so, replacing the values with your Slack app identifiers and customizing as desired:

```ini
[slack]
client-id = xxxxxxxxxx.xxxxxxxxxxxxx
client-secret = xxxxxxxxxxxxxxxxxxxxxxxx
oauth-callback-port = 8103
scopes = chat:write,channels:read
```

Then run the script:

```bash
./slack_oauth.py
```

A tab will open in your web browser to confirm the OAuth consent, and then the access token will be written to the terminal via stdout.

The result is cached in `.slack.conf` so that if you run it again, it doesn't have to re-run the entire flow.
