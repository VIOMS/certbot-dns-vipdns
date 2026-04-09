"""Tests for certbot-dns-vipdns."""
# pylint: disable=protected-access

import json
import os
import tempfile
import unittest
from unittest import mock

import responses as responses_lib

from certbot import errors
from certbot_dns_vipdns.dns_vipdns import Authenticator, _VipdnsClient, _load_credentials_file
from certbot_dns_vipdns.fakes import DOMAIN, FAKE_TOKEN, FAKE_URL, VALIDATION, VALIDATION_NAME


class VipdnsClientTest(unittest.TestCase):
    def setUp(self):
        self.client = _VipdnsClient(FAKE_URL, FAKE_TOKEN)

    def test_token_sent_in_header(self):
        self.assertEqual(self.client.session.headers['X-API-TOKEN'], FAKE_TOKEN)

    def test_trailing_slash_stripped_from_url(self):
        client = _VipdnsClient(f'{FAKE_URL}/', FAKE_TOKEN)
        self.assertEqual(client._api_url, FAKE_URL)

    @responses_lib.activate
    def test_add_txt_record_success(self):
        responses_lib.add(responses_lib.POST, f'{FAKE_URL}/api/v1/letsencrypt', status=200)

        self.client.add_txt_record(DOMAIN, VALIDATION_NAME, VALIDATION)

        self.assertEqual(len(responses_lib.calls), 1)
        body = json.loads(responses_lib.calls[0].request.body)
        self.assertEqual(body['domain'], DOMAIN)
        self.assertEqual(body['name'], VALIDATION_NAME)
        self.assertEqual(body['content'], VALIDATION)

    @responses_lib.activate
    def test_del_txt_record_success(self):
        responses_lib.add(responses_lib.DELETE, f'{FAKE_URL}/api/v1/letsencrypt', status=204)

        self.client.del_txt_record(DOMAIN, VALIDATION_NAME, VALIDATION)

        self.assertEqual(len(responses_lib.calls), 1)
        body = json.loads(responses_lib.calls[0].request.body)
        self.assertEqual(body['domain'], DOMAIN)
        self.assertEqual(body['name'], VALIDATION_NAME)
        self.assertEqual(body['content'], VALIDATION)

    @responses_lib.activate
    def test_add_txt_record_error_response(self):
        responses_lib.add(
            responses_lib.POST,
            f'{FAKE_URL}/api/v1/letsencrypt',
            status=403,
            json={'message': 'Forbidden'},
        )

        with self.assertRaises(errors.PluginError) as ctx:
            self.client.add_txt_record(DOMAIN, VALIDATION_NAME, VALIDATION)

        self.assertIn('403', str(ctx.exception))
        self.assertIn('Forbidden', str(ctx.exception))

    @responses_lib.activate
    def test_del_txt_record_error_response(self):
        responses_lib.add(responses_lib.DELETE, f'{FAKE_URL}/api/v1/letsencrypt', status=404)

        with self.assertRaises(errors.PluginError):
            self.client.del_txt_record(DOMAIN, VALIDATION_NAME, VALIDATION)

    @responses_lib.activate
    def test_error_response_malformed_json(self):
        responses_lib.add(
            responses_lib.POST,
            f'{FAKE_URL}/api/v1/letsencrypt',
            status=500,
            body='Internal Server Error',
        )

        with self.assertRaises(errors.PluginError):
            self.client.add_txt_record(DOMAIN, VALIDATION_NAME, VALIDATION)


class AuthenticatorTest(unittest.TestCase):
    def setUp(self):
        with mock.patch('certbot.plugins.dns_common.DNSAuthenticator.__init__'):
            self.auth = Authenticator(mock.MagicMock(), 'dns-vipdns')
        self.auth._api_url = FAKE_URL
        self.auth._api_token = FAKE_TOKEN

    def test_perform(self):
        mock_client = mock.MagicMock()
        self.auth._get_vipdns_client = mock.MagicMock(return_value=mock_client)

        self.auth._perform(DOMAIN, VALIDATION_NAME, VALIDATION)

        mock_client.add_txt_record.assert_called_once_with(DOMAIN, VALIDATION_NAME, VALIDATION)

    def test_perform_wildcard_strips_prefix(self):
        mock_client = mock.MagicMock()
        self.auth._get_vipdns_client = mock.MagicMock(return_value=mock_client)

        self.auth._perform('*.example.com', '_acme-challenge.example.com', VALIDATION)

        mock_client.add_txt_record.assert_called_once_with(
            'example.com', '_acme-challenge.example.com', VALIDATION
        )

    def test_cleanup(self):
        mock_client = mock.MagicMock()
        self.auth._get_vipdns_client = mock.MagicMock(return_value=mock_client)

        self.auth._cleanup(DOMAIN, VALIDATION_NAME, VALIDATION)

        mock_client.del_txt_record.assert_called_once_with(DOMAIN, VALIDATION_NAME, VALIDATION)

    def test_credentials_from_ini(self):
        mock_credentials = mock.MagicMock()
        mock_credentials.conf.side_effect = {
            'api_url': 'https://vipdns.test',
            'api_token': 'ini-token',
        }.__getitem__

        with mock.patch.object(self.auth, 'conf', side_effect={
            'api-url': None,
            'api-token': None,
        }.get):
            with mock.patch.object(self.auth, '_configure_credentials', return_value=mock_credentials):
                self.auth._setup_credentials()

        self.assertEqual(self.auth._api_url, 'https://vipdns.test')
        self.assertEqual(self.auth._api_token, 'ini-token')

    def test_cli_flags_override_ini(self):
        with mock.patch.object(self.auth, 'conf', side_effect={
            'api-url': 'https://cli.vipdns.test',
            'api-token': 'cli-token',
        }.get):
            with mock.patch.object(self.auth, '_configure_credentials') as mock_configure:
                self.auth._setup_credentials()
                mock_configure.assert_not_called()

        self.assertEqual(self.auth._api_url, 'https://cli.vipdns.test')
        self.assertEqual(self.auth._api_token, 'cli-token')

    def test_missing_credentials_raises(self):
        with mock.patch.object(self.auth, 'conf', return_value=None):
            with mock.patch.object(
                self.auth,
                '_configure_credentials',
                side_effect=errors.PluginError('No credentials file'),
            ):
                with self.assertRaises(errors.PluginError):
                    self.auth._setup_credentials()

    def test_more_info_returns_string(self):
        self.assertIsInstance(self.auth.more_info(), str)

    def test_setup_credentials_from_json(self):
        path = tempfile.mkstemp(suffix='.json')[1]
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write('{"api_url": "https://vipdns.test", "api_token": "json-token"}')
            with mock.patch.object(self.auth, 'conf', side_effect={
                'api-url': None,
                'api-token': None,
                'credentials': path,
            }.get):
                self.auth._setup_credentials()
            self.assertEqual(self.auth._api_url, 'https://vipdns.test')
            self.assertEqual(self.auth._api_token, 'json-token')
        finally:
            os.unlink(path)


class LoadCredentialsFileTest(unittest.TestCase):
    def _write_temp(self, content: str, suffix: str) -> str:
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, 'w') as f:
            f.write(content)
        return path

    def test_load_credentials_json(self):
        path = self._write_temp(
            '{"api_url": "https://vipdns.test", "api_token": "json-token"}',
            '.json',
        )
        try:
            url, token = _load_credentials_file(path)
            self.assertEqual(url, 'https://vipdns.test')
            self.assertEqual(token, 'json-token')
        finally:
            os.unlink(path)

    def test_load_credentials_yaml(self):
        path = self._write_temp(
            'api_url: https://vipdns.test\napi_token: yaml-token\n',
            '.yaml',
        )
        try:
            url, token = _load_credentials_file(path)
            self.assertEqual(url, 'https://vipdns.test')
            self.assertEqual(token, 'yaml-token')
        finally:
            os.unlink(path)

    def test_load_credentials_yml_extension(self):
        path = self._write_temp(
            'api_url: https://vipdns.test\napi_token: yml-token\n',
            '.yml',
        )
        try:
            url, token = _load_credentials_file(path)
            self.assertEqual(url, 'https://vipdns.test')
            self.assertEqual(token, 'yml-token')
        finally:
            os.unlink(path)

    def test_load_credentials_missing_token_raises(self):
        path = self._write_temp('{"api_url": "https://vipdns.test"}', '.json')
        try:
            with self.assertRaises(errors.PluginError) as ctx:
                _load_credentials_file(path)
            self.assertIn('api_token', str(ctx.exception))
        finally:
            os.unlink(path)

    def test_load_credentials_missing_url_returns_none(self):
        path = self._write_temp('{"api_token": "token-only"}', '.json')
        try:
            url, token = _load_credentials_file(path)
            self.assertIsNone(url)
            self.assertEqual(token, 'token-only')
        finally:
            os.unlink(path)

    def test_load_credentials_malformed_json_raises(self):
        path = self._write_temp('{not valid json}', '.json')
        try:
            with self.assertRaises(errors.PluginError):
                _load_credentials_file(path)
        finally:
            os.unlink(path)

    def test_load_credentials_malformed_yaml_raises(self):
        path = self._write_temp('[unclosed bracket', '.yaml')
        try:
            with self.assertRaises(errors.PluginError):
                _load_credentials_file(path)
        finally:
            os.unlink(path)
