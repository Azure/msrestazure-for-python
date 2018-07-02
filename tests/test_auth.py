#--------------------------------------------------------------------------
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
import datetime
import json
import sys
import time
import unittest
try:
    from unittest import mock
except ImportError:
    import mock

from requests import HTTPError, Session
from requests_oauthlib import OAuth2Session
import oauthlib
import adal
import httpretty

from msrestazure import AzureConfiguration
from msrestazure import azure_active_directory
from msrestazure.azure_active_directory import (
    AADMixin,
    ServicePrincipalCredentials,
    UserPassCredentials,
    AADTokenCredentials,
    AdalAuthentication,
    MSIAuthentication,
    get_msi_token,
    get_msi_token_webapp
)
from msrest.exceptions import TokenExpiredError, AuthenticationError
from requests import ConnectionError, HTTPError

import pytest

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
    @mock.patch('msrestazure.azure_active_directory.keyring')
    def test_store_token_boom(self, mock_keyring):

        def boom(*args, **kwargs):
            raise Exception("Boom!")
        mock_keyring.set_password = boom

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

    @httpretty.activate
    def test_msi_vm(self):

        # Test legacy MSI, with no MSI_ENDPOINT

        json_payload = {
            'token_type': "TokenType",
            "access_token": "AccessToken"
        }
        httpretty.register_uri(httpretty.POST,
                               'http://localhost:666/oauth2/token',
                               body=json.dumps(json_payload),
                               content_type="application/json")

        token_type, access_token, token_entry = get_msi_token("whatever", port=666)
        assert token_type == "TokenType"
        assert access_token == "AccessToken"
        assert token_entry == json_payload

        httpretty.register_uri(httpretty.POST,
                               'http://localhost:42/oauth2/token',
                               status=503,
                               content_type="application/json")

        with self.assertRaises(HTTPError):
            get_msi_token("whatever", port=42)

        # Test MSI_ENDPOINT

        json_payload = {
            'token_type': "TokenType",
            "access_token": "AccessToken"
        }
        httpretty.register_uri(httpretty.POST,
                               'http://random.org/yadadada',
                               body=json.dumps(json_payload),
                               content_type="application/json")

        with mock.patch('os.environ', {'MSI_ENDPOINT': 'http://random.org/yadadada'}):
            token_type, access_token, token_entry = get_msi_token("whatever")
            assert token_type == "TokenType"
            assert access_token == "AccessToken"
            assert token_entry == json_payload

        # Test MSIAuthentication with no MSI_ENDPOINT and no APPSETTING_WEBSITE_SITE_NAME is IMDS

        json_payload = {
            'token_type': "TokenTypeIMDS",
            "access_token": "AccessToken"
        }
        httpretty.register_uri(httpretty.GET,
                               'http://169.254.169.254/metadata/identity/oauth2/token',
                               body=json.dumps(json_payload),
                               content_type="application/json")

        credentials = MSIAuthentication()
        assert credentials.scheme == "TokenTypeIMDS"
        assert credentials.token == json_payload

        # Test MSIAuthentication with MSI_ENDPOINT and no APPSETTING_WEBSITE_SITE_NAME is MSI_ENDPOINT

        json_payload = {
            'token_type': "TokenTypeMSI_ENDPOINT",
            "access_token": "AccessToken"
        }
        httpretty.register_uri(httpretty.POST,
                               'http://random.org/yadadada',
                               body=json.dumps(json_payload),
                               content_type="application/json")

        with mock.patch('os.environ', {'MSI_ENDPOINT': 'http://random.org/yadadada'}):
            credentials = MSIAuthentication()
            assert credentials.scheme == "TokenTypeMSI_ENDPOINT"
            assert credentials.token == json_payload

        # WebApp

        json_payload = {
            'token_type': "TokenTypeWebApp",
            "access_token": "AccessToken"
        }
        httpretty.register_uri(httpretty.GET,
                               'http://127.0.0.1:41741/MSI/token/?resource=foo&api-version=2017-09-01',
                               body=json.dumps(json_payload),
                               content_type="application/json")

        app_service_env = {
            'APPSETTING_WEBSITE_SITE_NAME': 'Website name',
            'MSI_ENDPOINT': 'http://127.0.0.1:41741/MSI/token',
            'MSI_SECRET': '69418689F1E342DD946CB82994CDA3CB'
        }
        with mock.patch.dict('os.environ', app_service_env):
            credentials = MSIAuthentication(resource="foo")
            assert credentials.scheme == "TokenTypeWebApp"
            assert credentials.token == json_payload


    @httpretty.activate
    def test_msi_vm_imds_retry(self):

        json_payload = {
            'token_type': "TokenTypeIMDS",
            "access_token": "AccessToken"
        }
        httpretty.register_uri(httpretty.GET,
                               'http://169.254.169.254/metadata/identity/oauth2/token',
                               status=404)
        httpretty.register_uri(httpretty.GET,
                               'http://169.254.169.254/metadata/identity/oauth2/token',
                               status=429)
        httpretty.register_uri(httpretty.GET,
                               'http://169.254.169.254/metadata/identity/oauth2/token',
                               status=599)
        httpretty.register_uri(httpretty.GET,
                               'http://169.254.169.254/metadata/identity/oauth2/token',
                               body=json.dumps(json_payload),
                               content_type="application/json")
        credentials = MSIAuthentication()
        assert credentials.scheme == "TokenTypeIMDS"
        assert credentials.token == json_payload


    @httpretty.activate
    def test_msi_vm_imds_no_retry_on_bad_error(self):

        httpretty.register_uri(httpretty.GET,
                               'http://169.254.169.254/metadata/identity/oauth2/token',
                               status=499)
        with self.assertRaises(HTTPError) as cm:
            credentials = MSIAuthentication()


@pytest.mark.slow
def test_refresh_userpassword_no_common_session(user_password):
    user, password = user_password

    creds = UserPassCredentials(user, password)

    # Basic scenarion, I recreate the session each time
    session = creds.signed_session()

    response = session.get("https://management.azure.com/subscriptions?api-version=2016-06-01")
    response.raise_for_status() # Should never raise

    # Hacking the token time
    creds.token['expires_on'] = time.time() - 10
    creds.token['expires_at'] = creds.token['expires_on']

    try:
        session = creds.signed_session()
        response = session.get("https://management.azure.com/subscriptions?api-version=2016-06-01")
        pytest.fail("Requests should have failed")
    except oauthlib.oauth2.rfc6749.errors.TokenExpiredError:
        session = creds.refresh_session()
        response = session.get("https://management.azure.com/subscriptions?api-version=2016-06-01")
        response.raise_for_status() # Should never raise

@pytest.mark.slow
def test_refresh_userpassword_common_session(user_password):
    user, password = user_password

    creds = UserPassCredentials(user, password)
    root_session = Session()

    # Basic scenarion, I recreate the session each time
    session = creds.signed_session(root_session)

    response = session.get("https://management.azure.com/subscriptions?api-version=2016-06-01")
    response.raise_for_status() # Should never raise

    # Hacking the token time
    creds.token['expires_on'] = time.time() - 10
    creds.token['expires_at'] = creds.token['expires_on']

    try:
        session = creds.signed_session(root_session)
        response = session.get("https://management.azure.com/subscriptions?api-version=2016-06-01")
        pytest.fail("Requests should have failed")
    except oauthlib.oauth2.rfc6749.errors.TokenExpiredError:
        session = creds.refresh_session(root_session)
        response = session.get("https://management.azure.com/subscriptions?api-version=2016-06-01")
        response.raise_for_status() # Should never raise

@pytest.mark.slow
def test_refresh_aadtokencredentials_no_common_session(user_password):
    user, password = user_password

    context = adal.AuthenticationContext('https://login.microsoftonline.com/common')
    token = context.acquire_token_with_username_password(
        'https://management.core.windows.net/',
        user,
        password,
        '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
    )
    creds = AADTokenCredentials(token)

    # Basic scenarion, I recreate the session each time
    session = creds.signed_session()

    response = session.get("https://management.azure.com/subscriptions?api-version=2016-06-01")
    response.raise_for_status() # Should never raise

    # Hacking the token time
    creds.token['expires_on'] = time.time() - 10
    creds.token['expires_at'] = creds.token['expires_on']

    try:
        session = creds.signed_session()
        response = session.get("https://management.azure.com/subscriptions?api-version=2016-06-01")
        pytest.fail("Requests should have failed")
    except oauthlib.oauth2.rfc6749.errors.TokenExpiredError:
        session = creds.refresh_session()
        response = session.get("https://management.azure.com/subscriptions?api-version=2016-06-01")
        response.raise_for_status() # Should never raise

@pytest.mark.slow
def test_refresh_aadtokencredentials_common_session(user_password):
    user, password = user_password

    context = adal.AuthenticationContext('https://login.microsoftonline.com/common')
    token = context.acquire_token_with_username_password(
        'https://management.core.windows.net/',
        user,
        password,
        '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
    )
    creds = AADTokenCredentials(token)

    root_session = Session()

    # Basic scenarion, I recreate the session each time
    session = creds.signed_session(root_session)

    response = session.get("https://management.azure.com/subscriptions?api-version=2016-06-01")
    response.raise_for_status() # Should never raise

    # Hacking the token time
    creds.token['expires_on'] = time.time() - 10
    creds.token['expires_at'] = creds.token['expires_on']

    try:
        session = creds.signed_session(root_session)
        response = session.get("https://management.azure.com/subscriptions?api-version=2016-06-01")
        pytest.fail("Requests should have failed")
    except oauthlib.oauth2.rfc6749.errors.TokenExpiredError:
        session = creds.refresh_session(root_session)
        response = session.get("https://management.azure.com/subscriptions?api-version=2016-06-01")
        response.raise_for_status() # Should never raise

@pytest.mark.slow
def test_refresh_aadtokencredentials_existing_session(user_password):
    user, password = user_password

    context = adal.AuthenticationContext('https://login.microsoftonline.com/common')
    token = context.acquire_token_with_username_password(
        'https://management.core.windows.net/',
        user,
        password,
        '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
    )
    creds = AADTokenCredentials(token)

    root_session = Session()

    creds.signed_session(root_session)

    response = root_session.get("https://management.azure.com/subscriptions?api-version=2016-06-01")
    response.raise_for_status()  # Should never raise

    # Hacking the token time
    creds.token['expires_on'] = time.time() - 10
    creds.token['expires_at'] = creds.token['expires_on']

    try:
        creds.signed_session(root_session)
        response = root_session.get("https://management.azure.com/subscriptions?api-version=2016-06-01")
        pytest.fail("Requests should have failed")
    except oauthlib.oauth2.rfc6749.errors.TokenExpiredError:
        creds.refresh_session(root_session)
        response = root_session.get("https://management.azure.com/subscriptions?api-version=2016-06-01")
        response.raise_for_status()  # Should never raise

if __name__ == '__main__':
    unittest.main()
