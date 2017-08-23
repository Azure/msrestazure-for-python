﻿#--------------------------------------------------------------------------
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the ""Software""), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
#--------------------------------------------------------------------------

import json
import sys
import unittest
try:
    from unittest import mock
except ImportError:
    import mock

from requests_oauthlib import OAuth2Session
import oauthlib
import adal

from msrestazure import AzureConfiguration
from msrestazure import azure_active_directory
from msrestazure.azure_active_directory import (
    AADMixin,
    ServicePrincipalCredentials,
    UserPassCredentials,
    AdalAuthentication
)
from msrest.exceptions import TokenExpiredError, AuthenticationError
from requests import ConnectionError


class TestServicePrincipalCredentials(unittest.TestCase):

    def setUp(self):
        self.cfg = AzureConfiguration("https://my_service.com")
        return super(TestServicePrincipalCredentials, self).setUp()

    def test_http(self):

        test_uri = "http://my_service.com"
        build = azure_active_directory._http(test_uri, "path")

        self.assertEqual(build, "http://my_service.com/path")

        test_uri = "HTTPS://my_service.com"
        build = azure_active_directory._http(test_uri, "path")

        self.assertEqual(build, "http://my_service.com/path")

        test_uri = "my_service.com"
        build = azure_active_directory._http(test_uri, "path")

        self.assertEqual(build, "http://my_service.com/path")

    def test_https(self):

        test_uri = "http://my_service.com"
        build = azure_active_directory._https(test_uri, "path")

        self.assertEqual(build, "https://my_service.com/path")

        test_uri = "HTTPS://my_service.com"
        build = azure_active_directory._https(test_uri, "path")

        self.assertEqual(build, "https://my_service.com/path")

        test_uri = "my_service.com"
        build = azure_active_directory._https(test_uri, "path")

        self.assertEqual(build, "https://my_service.com/path")


    def test_check_state(self):

        mix = AADMixin(None, None)
        mix.state = "abc"

        with self.assertRaises(ValueError):
            mix._check_state("server?test")
        with self.assertRaises(ValueError):
            mix._check_state("server?test&abc")
        with self.assertRaises(ValueError):
            mix._check_state("server?test&state=xyx")
        with self.assertRaises(ValueError):
            mix._check_state("server?test&state=xyx&")
        with self.assertRaises(ValueError):
            mix._check_state("server?test&state=abcd&")
        mix._check_state("server?test&state=abc&")

    def test_convert_token(self):

        mix = AADMixin(None, None)
        token = {'access_token':'abc', 'expires_on':123, 'refresh_token':'asd'}
        self.assertEqual(mix._convert_token(token), token)

        caps = {'accessToken':'abc', 'expiresOn':123, 'refreshToken':'asd'}
        self.assertEqual(mix._convert_token(caps), token)

        caps = {'ACCessToken':'abc', 'Expires_On':123, 'REFRESH_TOKEN':'asd'}
        self.assertEqual(mix._convert_token(caps), token)

    @mock.patch('msrestazure.azure_active_directory.keyring')
    def test_store_token(self, mock_keyring):

        mix = AADMixin(None, None)
        mix.cred_store = "store_name"
        mix.store_key = "client_id"
        mix._default_token_cache({'token_type':'1', 'access_token':'2'})

        mock_keyring.set_password.assert_called_with(
            "store_name", "client_id",
            str({'token_type':'1', 'access_token':'2'}))

    @unittest.skipIf(sys.version_info < (3,4), "assertLogs not supported before 3.4")
    @mock.patch('msrestazure.azure_active_directory.keyring.set_password')
    def test_store_token_boom(self, mock_keyring):

        mock_keyring.side_effect = Exception('Boom!')

        mix = AADMixin(None, None)
        mix.cred_store = "store_name"
        mix.store_key = "client_id"
        with self.assertLogs('msrestazure.azure_active_directory', level="WARNING"):
            mix._default_token_cache({'token_type':'1', 'access_token':'2'})

    @mock.patch('msrestazure.azure_active_directory.keyring')
    def test_clear_token(self, mock_keyring):

        mix = AADMixin(None, None)
        mix.cred_store = "store_name"
        mix.store_key = "client_id"
        mix.clear_cached_token()

        mock_keyring.delete_password.assert_called_with(
            "store_name", "client_id")

    @mock.patch('msrestazure.azure_active_directory.keyring')
    def test_credentials_get_stored_auth(self, mock_keyring):

        mix = AADMixin(None, None)
        mix.cred_store = "store_name"
        mix.store_key = "client_id"
        mix.signed_session = mock.Mock()

        mock_keyring.get_password.return_value = None

        with self.assertRaises(ValueError):
            mix._retrieve_stored_token()

        mock_keyring.get_password.assert_called_with(
            "store_name", "client_id")

        mock_keyring.get_password.return_value = str(
            {'token_type':'1', 'access_token':'2'})

        mix._retrieve_stored_token()
        mock_keyring.get_password.assert_called_with("store_name", "client_id")

    @mock.patch.object(AADMixin, '_retrieve_stored_token')
    def test_credentials_retrieve_session(self, mock_retrieve):

        creds = ServicePrincipalCredentials.retrieve_session("client_id")
        mock_retrieve.asset_called_with(mock.ANY)

        mock_retrieve.side_effect = ValueError("No stored token")
        with self.assertRaises(ValueError):
            ServicePrincipalCredentials.retrieve_session("client_id")

        mock_retrieve.side_effect = TokenExpiredError("Token expired")
        with self.assertRaises(TokenExpiredError):
            ServicePrincipalCredentials.retrieve_session("client_id")

    @mock.patch('msrestazure.azure_active_directory.oauth')
    def test_credentials_signed_session(self, mock_requests):

        creds = mock.create_autospec(ServicePrincipalCredentials)
        creds._parse_token = lambda: AADMixin._parse_token(creds)
        creds.id = 'client_id'
        creds.token_uri = "token_uri"
        creds.resource = "resource"

        creds.token = {'expires_at':'1',
                       'expires_in':'2',
                       'refresh_token':"test"}

        AADMixin.signed_session(creds)
        mock_requests.OAuth2Session.assert_called_with(
            'client_id',
            token=creds.token,
            auto_refresh_url='token_uri',
            auto_refresh_kwargs={'client_id':'client_id', 'resource':'resource'},
            token_updater=creds._default_token_cache)

    def test_service_principal(self):

        creds = mock.create_autospec(ServicePrincipalCredentials)
        session = mock.create_autospec(OAuth2Session)
        session.__enter__.return_value = session
        creds._setup_session.return_value = session

        session.fetch_token.return_value = {
            'expires_at':'1',
            'expires_in':'2'}

        creds.token_uri = "token_uri"
        creds.verify = True
        creds.id = 123
        creds.secret = 'secret'
        creds.resource = 'resource'
        creds.timeout = 12
        mock_proxies = {
            'http': 'http://myproxy:8080',
            'https': 'https://myproxy:8080',
        }
        creds.proxies = mock_proxies

        ServicePrincipalCredentials.set_token(creds)
        self.assertEqual(creds.token, session.fetch_token.return_value)
        session.fetch_token.assert_called_with(
            "token_uri", client_id=123, client_secret='secret',
            resource='resource', response_type="client_credentials",
            verify=True, timeout=12, proxies=mock_proxies)

        session.fetch_token.side_effect = oauthlib.oauth2.OAuth2Error

        with self.assertRaises(AuthenticationError):
            ServicePrincipalCredentials.set_token(creds)

        session = mock.create_autospec(OAuth2Session)
        session.__enter__.return_value = session
        with mock.patch.object(
            ServicePrincipalCredentials, '_setup_session', return_value=session):

            proxies = {'http': 'http://myproxy:80'}
            creds = ServicePrincipalCredentials("client_id", "secret", 
                                                verify=False, tenant="private",
                                                proxies=proxies)

            session.fetch_token.assert_called_with(
                "https://login.microsoftonline.com/private/oauth2/token",
                client_id="client_id",
                client_secret='secret',
                resource='https://management.core.windows.net/',
                response_type="client_credentials",
                verify=False,
                timeout=None,
                proxies=proxies,
            )

        with mock.patch.object(
            ServicePrincipalCredentials, '_setup_session', return_value=session):

            creds = ServicePrincipalCredentials("client_id", "secret", china=True,
                                                verify=False, tenant="private")

            session.fetch_token.assert_called_with(
                "https://login.chinacloudapi.cn/private/oauth2/token",
                client_id="client_id", client_secret='secret',
                resource='https://management.core.chinacloudapi.cn/',
                response_type="client_credentials", verify=False, proxies=None, timeout=None)

    def test_user_pass_credentials(self):

        creds = mock.create_autospec(UserPassCredentials)
        session = mock.create_autospec(OAuth2Session)
        session.__enter__.return_value = session
        creds._setup_session.return_value = session

        session.fetch_token.return_value = {
            'expires_at':'1',
            'expires_in':'2'}

        creds.token_uri = "token_uri"
        creds.verify = True
        creds.username = "user"
        creds.password = 'pass'
        creds.secret = 'secret'
        creds.resource = 'resource'
        creds.timeout = 12
        creds.id = "id"
        mock_proxies = {
            'http': 'http://myproxy:8080',
            'https': 'https://myproxy:8080',
        }
        creds.proxies = mock_proxies

        UserPassCredentials.set_token(creds)
        self.assertEqual(creds.token, session.fetch_token.return_value)
        session.fetch_token.assert_called_with(
            "token_uri", client_id="id", username='user',
            client_secret="secret", password='pass', resource='resource', verify=True,
            timeout=12, proxies=mock_proxies
        )

        session.fetch_token.side_effect = oauthlib.oauth2.OAuth2Error

        with self.assertRaises(AuthenticationError):
            UserPassCredentials.set_token(creds)

        session = mock.create_autospec(OAuth2Session)
        session.__enter__.return_value = session
        with mock.patch.object(
            UserPassCredentials, '_setup_session', return_value=session):

            proxies = {'http': 'http://myproxy:8080'}
            creds = UserPassCredentials("my_username", "my_password", 
                                        verify=False, tenant="private", resource='resource',
                                        proxies=proxies)

            session.fetch_token.assert_called_with(
                "https://login.microsoftonline.com/private/oauth2/token",
                client_id='04b07795-8ddb-461a-bbee-02f9e1bf7b46', username='my_username',
                password='my_password', resource='resource', verify=False,
                proxies=proxies, timeout=None
            )

        with mock.patch.object(
            UserPassCredentials, '_setup_session', return_value=session):

            creds = UserPassCredentials("my_username", "my_password", client_id="client_id",
                                        verify=False, tenant="private", china=True)

            session.fetch_token.assert_called_with(
                "https://login.chinacloudapi.cn/private/oauth2/token",
                client_id="client_id", username='my_username',
                password='my_password', resource='https://management.core.chinacloudapi.cn/',
                verify=False, proxies=None, timeout=None)

    def test_adal_authentication(self):
        def success_auth():
            return {
                'tokenType': 'https',
                'accessToken': 'cryptictoken'
            }

        credentials = AdalAuthentication(success_auth)
        session = credentials.signed_session()
        self.assertEquals(session.headers['Authorization'], 'https cryptictoken')

        def error():
            raise adal.AdalError("You hacker", {})
        credentials = AdalAuthentication(error)
        with self.assertRaises(AuthenticationError) as cm:
            session = credentials.signed_session()

        def expired():
            raise adal.AdalError("Too late", {'error_description': "AADSTS70008: Expired"})
        credentials = AdalAuthentication(expired)
        with self.assertRaises(TokenExpiredError) as cm:
            session = credentials.signed_session()

        def connection_error():
            raise ConnectionError("Plug the network")
        credentials = AdalAuthentication(connection_error)
        with self.assertRaises(AuthenticationError) as cm:
            session = credentials.signed_session()

if __name__ == '__main__':
    unittest.main()
