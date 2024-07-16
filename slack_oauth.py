#!/usr/bin/env python3
import argparse
import configparser
import dataclasses
import http.server
import json
import logging
import pathlib
import ssl
import subprocess
import sys
import threading
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import KW_ONLY
from dataclasses import dataclass
from typing import ClassVar
from typing import Self

_SSL_KEY_PATH = pathlib.Path('.ssl.key')
_SSL_CERT_PATH = pathlib.Path('.ssl.crt')

_logger = logging.getLogger(__name__)

_parser = argparse.ArgumentParser(
    description='Perform Slack OAuth flow from the terminal.'
)

_parser.add_argument(
    '-f',
    '--force',
    action='store_true',
    dest='force',
    help='Force re-authentication; ignore cached `access-token` setting in config.',
)


@dataclass
class _Abort(Exception):
    message: str


@dataclass
class _Config:
    DEFAULT_CONFIG_PATH: ClassVar[pathlib.Path] = pathlib.Path('.slack.conf')

    _: KW_ONLY

    access_token: str | None
    client_id: str
    client_secret: str = dataclasses.field(repr=False)
    oauth_callback_port: int
    scopes: set[str]

    @classmethod
    def read(
        cls,
        path: pathlib.Path = pathlib.Path(DEFAULT_CONFIG_PATH),
    ) -> Self:
        if not path.is_file():
            raise ValueError(f'Missing config file: {str(path)}')

        parser = configparser.ConfigParser()
        parser.read_string(path.read_text())
        section = parser['slack']
        try:
            config = cls(
                access_token=section.get('access-token'),
                client_id=section['client-id'],
                client_secret=section['client-secret'],
                oauth_callback_port=int(section.get('oauth_callback_port', '8103')),
                scopes=set(section.get('scopes', 'chat:write').split(',')),
            )
        except KeyError as error:
            raise _Abort(f'Missing config setting: {error.args[0]!r}')
        return config

    def write(
        self,
        path: pathlib.Path = pathlib.Path(DEFAULT_CONFIG_PATH),
    ) -> None:
        parser = configparser.ConfigParser()
        parser['slack'] = {
            'client-id': self.client_id,
            'client-secret': self.client_secret,
            'oauth-callback-port': str(self.oauth_callback_port),
            'scopes': ','.join(sorted(self.scopes)),
        }
        if self.access_token:
            parser['slack']['access-token'] = self.access_token
        with path.open('w') as file:
            parser.write(file)


def _generate_private_key(key_path: pathlib.Path) -> str:
    if key_path.is_file():
        _logger.info('SSL key file exists: %s', str(key_path))
        key = key_path.read_text()

    else:
        _logger.info('Generating key...')
        key = subprocess.check_output(
            [
                'openssl',
                'genpkey',
                '-algorithm',
                'RSA',
                '-pkeyopt',
                'rsa_keygen_bits:2048',
            ],
            text=True,
        )

        _logger.info('Writing %r ...', str(key_path))
        key_path.write_text(key)

    _logger.debug('Key:\n%s', str(key))
    return key


def _generate_cert(
    cert_path: pathlib.Path,
    key_path: pathlib.Path,
) -> str:
    if _SSL_CERT_PATH.is_file():
        _logger.info('SSL cert file exists: %s', str(cert_path))
        cert = cert_path.read_text()

    else:
        _logger.info('Generating SSL CSR...')
        csr = subprocess.check_output(
            [
                'openssl',
                'req',
                '-new',
                '-key',
                str(key_path),
                '-subj',
                '/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=localhost',
            ],
            text=True,
        )

        _logger.info('Generating SSL cert...')
        cert = subprocess.check_output(
            [
                'openssl',
                'x509',
                '-req',
                '-days',
                '365',
                '-signkey',
                str(key_path),
                '-in',
                '/dev/stdin',
            ],
            input=csr,
            text=True,
        )

        _logger.info('Writing SSL cert file: %s', str(cert_path))
        cert_path.write_text(cert)

    _logger.debug('Cert:\n%s', str(cert))
    return cert


@dataclass
class _SlackOAuthFlow:
    _SCOPES: ClassVar[set[str]] = {'chat:write'}
    _TOKEN_URL: ClassVar[str] = 'https://slack.com/api/oauth.v2.access'

    config: _Config

    _access_token: str | None = None

    @property
    def _redirect_uri(self) -> str:
        return f'https://localhost:{self.config.oauth_callback_port}'

    @property
    def _authorization_url(self) -> str:
        return (
            'https://slack.com/oauth/v2/authorize'
            + '?'
            + urllib.parse.urlencode(
                {
                    'client_id': self.config.client_id,
                    'redirect_uri': self._redirect_uri,
                    'scope': ','.join(sorted(self._SCOPES)),
                }
            )
        )

    def _handle_oauth_callback(self, code: str) -> None:
        """Handles Slack OAuth callback by exchanging auth code for access token."""
        token_request_data = urllib.parse.urlencode(
            {
                'client_id': self.config.client_id,
                'client_secret': self.config.client_secret,
                'code': code,
                'redirect_uri': self._redirect_uri,
            }
        ).encode('utf-8')

        req = urllib.request.Request(
            self._TOKEN_URL, data=token_request_data, method='POST'
        )
        with urllib.request.urlopen(req) as response:
            if response.status != 200:
                raise ValueError('Error during token exchange:', response.read())
            response_data = json.loads(response.read())

        access_token = response_data.get('access_token')
        if not isinstance(access_token, str):
            raise ValueError('Missing `access_token` in token exchange response')

        self._access_token = access_token

    def _get_handler(self) -> type[http.server.SimpleHTTPRequestHandler]:
        flow = self

        class Handler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self) -> None:
                parsed_path = urllib.parse.urlparse(self.path)
                if parsed_path.path == '/':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    query_params = urllib.parse.parse_qs(parsed_path.query)
                    if 'code' in query_params:
                        auth_code = query_params['code'][0]
                        self.wfile.write(
                            b'Authorization successful. You can close this window.'
                        )
                        flow._handle_oauth_callback(auth_code)
                    else:
                        self.wfile.write(b'No authorization code found.')

                    self.server.shutdown()

        return Handler

    def _start_server(self) -> None:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(str(_SSL_CERT_PATH), str(_SSL_KEY_PATH))

        handler = self._get_handler()
        with http.server.ThreadingHTTPServer(
            ('', self.config.oauth_callback_port), handler
        ) as httpd:
            httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)

            print('Serving on port', self.config.oauth_callback_port, file=sys.stderr)
            httpd.serve_forever()

    def run(self) -> str:
        """Performs the Slack OAuth flow by running a local redirect handler, doing the
        token exchange, and capturing the access token.
        """
        _generate_private_key(_SSL_KEY_PATH)
        _generate_cert(_SSL_CERT_PATH, _SSL_KEY_PATH)

        server_thread = threading.Thread(target=self._start_server)
        server_thread.daemon = True
        server_thread.start()

        webbrowser.open(self._authorization_url)

        server_thread.join()

        assert self._access_token is not None
        return self._access_token


def _main() -> None:
    logging.basicConfig(level=logging.INFO)
    args = _parser.parse_args()

    try:
        config = _Config.read()
        if args.force or not config.access_token:
            config.access_token = _SlackOAuthFlow(config).run()
        print('Access token:', file=sys.stderr)
        print(config.access_token)  # write to stdout independently
        config.write()
    except _Abort as abort:
        print(abort.message + '\nAbort.', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    _main()
