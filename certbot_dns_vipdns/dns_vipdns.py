"""Certbot DNS authenticator plugin for VipDNS."""

import json
import logging
from pathlib import Path

import requests
import yaml
from certbot import errors
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


def _load_credentials_file(path: str) -> tuple[str | None, str]:
    """Parse a JSON or YAML credentials file; return (api_url, api_token) or raise PluginError."""
    suffix = Path(path).suffix.lower()
    try:
        with open(path, encoding='utf-8') as f:
            if suffix == '.json':
                data = json.load(f)
            else:  # .yaml or .yml
                data = yaml.safe_load(f)
    except FileNotFoundError as exc:
        raise errors.PluginError(f'Credentials file not found: {path}') from exc
    except json.JSONDecodeError as exc:
        raise errors.PluginError(f'Invalid JSON in credentials file {path}: {exc}')
    except yaml.YAMLError as exc:
        raise errors.PluginError(f'Invalid YAML in credentials file {path}: {exc}')

    if not data.get('api_token'):
        raise errors.PluginError(f'Missing required key "api_token" in credentials file: {path}')

    return data.get('api_url'), data['api_token']


class _VipdnsClient:
    """HTTP client for the VipDNS LetsEncrypt API."""

    def __init__(self, api_url: str, api_token: str) -> None:
        self._api_url = api_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({'X-API-TOKEN': api_token})

    def add_txt_record(self, domain: str, name: str, content: str) -> None:
        """POST /v1/letsencrypt to create a TXT challenge record."""
        url = f'{self._api_url}/api/v1/letsencrypt'
        response = self.session.post(url, json={'domain': domain, 'name': name, 'content': content})
        self._check_response(response)

    def del_txt_record(self, domain: str, name: str, content: str) -> None:
        """DELETE /v1/letsencrypt to remove a TXT challenge record."""
        url = f'{self._api_url}/api/v1/letsencrypt'
        response = self.session.delete(url, json={'domain': domain, 'name': name, 'content': content})
        self._check_response(response)

    def _check_response(self, response: requests.Response) -> None:
        if not response.ok:
            try:
                message = response.json().get('message', response.text)
            except ValueError:
                message = response.text or str(response.status_code)
            raise errors.PluginError(f'VipDNS API error {response.status_code}: {message}')


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for VipDNS. Automates DNS-01 challenges via the VipDNS LetsEncrypt API."""

    description = 'Obtain certificates using a DNS TXT record (if you are using VipDNS).'

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._api_url: str | None = None
        self._api_token: str | None = None
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add, default_propagation_seconds: int = 60) -> None:
        super().add_parser_arguments(add, default_propagation_seconds=default_propagation_seconds)
        add('credentials', help='VipDNS credentials INI file.')
        add('api-url', default='https://vipdns.nl', help='VipDNS base URL (overrides credentials file).')
        add('api-token', help='VipDNS API token (overrides credentials file).')

    def more_info(self) -> str:
        return 'This plugin automates DNS-01 challenges using the VipDNS LetsEncrypt API.'

    def _setup_credentials(self) -> None:
        cli_url = self.conf('api-url')
        cli_token = self.conf('api-token')

        if cli_url and cli_token:
            self._api_url = cli_url.rstrip('/')
            self._api_token = cli_token
            return

        creds_path = self.conf('credentials')
        if creds_path and Path(creds_path).suffix.lower() in ('.json', '.yaml', '.yml'):
            api_url, api_token = _load_credentials_file(creds_path)
            self._api_url = (cli_url or api_url).rstrip('/')
            self._api_token = cli_token or api_token
        else:
            self.credentials = self._configure_credentials(
                'credentials',
                'VipDNS credentials INI file',
                {'api_token': 'VipDNS API token.'},
            )
            self._api_url = (cli_url or self.credentials.conf('api_url')).rstrip('/')
            self._api_token = cli_token or self.credentials.conf('api_token')

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        base_domain = domain[2:] if domain.startswith('*.') else domain
        self._get_vipdns_client().add_txt_record(base_domain, validation_name, validation)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        base_domain = domain[2:] if domain.startswith('*.') else domain
        self._get_vipdns_client().del_txt_record(base_domain, validation_name, validation)

    def _get_vipdns_client(self) -> '_VipdnsClient':
        return _VipdnsClient(self._api_url, self._api_token)
