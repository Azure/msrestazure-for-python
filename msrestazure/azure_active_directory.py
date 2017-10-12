# --------------------------------------------------------------------------
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the ""Software""), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
# --------------------------------------------------------------------------

import ast
import os
import logging
import re
import time
import warnings
try:
    from urlparse import urlparse, parse_qs
except ImportError:
    from urllib.parse import urlparse, parse_qs

import adal
from oauthlib.oauth2 import BackendApplicationClient, LegacyApplicationClient
from oauthlib.oauth2.rfc6749.errors import (
    InvalidGrantError,
    MismatchingStateError,
    OAuth2Error,
    TokenExpiredError)
from requests import RequestException, ConnectionError
import requests
import requests_oauthlib as oauth

try:
    import keyring
except Exception as err:
    keyring = False
    KEYRING_EXCEPTION = err

from msrest.authentication import OAuthTokenAuthentication, Authentication, BasicTokenAuthentication
from msrest.exceptions import TokenExpiredError as Expired
from msrest.exceptions import AuthenticationError, raise_with_traceback

from msrestazure.azure_cloud import AZURE_CHINA_CLOUD, AZURE_PUBLIC_CLOUD

_LOGGER = logging.getLogger(__name__)

if not keyring:
    _LOGGER.warning("Cannot load keyring on your system: %s", KEYRING_EXCEPTION)

def _build_url(uri, paths, scheme):
    """Combine URL parts.

    :param str uri: The base URL.
    :param list paths: List of strings that make up the URL.
    :param str scheme: The URL scheme, 'http' or 'https'.
    :rtype: str
    :return: Combined, formatted URL.
    """
    path = [str(p).strip('/') for p in paths]
    combined_path = '/'.join(path)
    parsed_url = urlparse(uri)
    replaced = parsed_url._replace(scheme=scheme)
    if combined_path:
        path = '/'.join([replaced.path, combined_path])
        replaced = replaced._replace(path=path)

    new_url = replaced.geturl()
    new_url = new_url.replace('///', '//')
    return new_url


def _http(uri, *extra):
    """Convert https URL to http.

    :param str uri: The base URL.
    :param str extra: Additional URL paths (optional).
    :rtype: str
    :return: An HTTP URL.
    """
    return _build_url(uri, extra, 'http')


def _https(uri, *extra):
    """Convert http URL to https.

    :param str uri: The base URL.
    :param str extra: Additional URL paths (optional).
    :rtype: str
    :return: An HTTPS URL.
    """
    return _build_url(uri, extra, 'https')


class AADMixin(OAuthTokenAuthentication):
    """Mixin for Authentication object.
    Provides some AAD functionality:
    - State validation
    - Token caching and retrieval
    - Default AAD configuration
    """
    _token_uri = "/oauth2/token"
    _auth_uri = "/oauth2/authorize"
    _tenant = "common"
    _keyring = "AzureAAD"
    _case = re.compile('([a-z0-9])([A-Z])')

    def _configure(self, **kwargs):
        """Configure authentication endpoint.

        Optional kwargs may include:
            - cloud_environment (msrestazure.azure_cloud.Cloud): A targeted cloud environment
            - china (bool): Configure auth for China-based service,
              default is 'False'.
            - tenant (str): Alternative tenant, default is 'common'.
            - auth_uri (str): Alternative authentication endpoint.
            - token_uri (str): Alternative token retrieval endpoint.
            - resource (str): Alternative authentication resource, default
              is 'https://management.core.windows.net/'.
            - verify (bool): Verify secure connection, default is 'True'.
            - keyring (str): Name of local token cache, default is 'AzureAAD'.
            - timeout (int): Timeout of the request in seconds.
            - proxies (dict): Dictionary mapping protocol or protocol and 
              hostname to the URL of the proxy.
        """
        if kwargs.get('china'):
            err_msg = ("china parameter is deprecated, "
                       "please use "
                       "cloud_environment=msrestazure.azure_cloud.AZURE_CHINA_CLOUD")
            warnings.warn(err_msg, DeprecationWarning)
            self.cloud_environment = AZURE_CHINA_CLOUD
        else:
            self.cloud_environment = AZURE_PUBLIC_CLOUD
        self.cloud_environment = kwargs.get('cloud_environment', self.cloud_environment)

        auth_endpoint = self.cloud_environment.endpoints.active_directory
        resource = self.cloud_environment.endpoints.management

        tenant = kwargs.get('tenant', self._tenant)
        self.auth_uri = kwargs.get('auth_uri', _https(
            auth_endpoint, tenant, self._auth_uri))
        self.token_uri = kwargs.get('token_uri', _https(
            auth_endpoint, tenant, self._token_uri))
        self.verify = kwargs.get('verify', True)
        self.cred_store = kwargs.get('keyring', self._keyring)
        self.resource = kwargs.get('resource', resource)
        self.proxies = kwargs.get('proxies')
        self.timeout = kwargs.get('timeout')
        self.state = oauth.oauth2_session.generate_token()
        self.store_key = "{}_{}".format(
            auth_endpoint.strip('/'), self.store_key)

    def _check_state(self, response):
        """Validate state returned by AAD server.

        :param str response: URL returned by server redirect.
        :raises: ValueError if state does not match that of the request.
        :rtype: None
        """
        query = parse_qs(urlparse(response).query)
        if self.state not in query.get('state', []):
            raise ValueError(
                "State received from server does not match that of request.")

    def _convert_token(self, token):
        """Convert token fields from camel case.

        :param dict token: An authentication token.
        :rtype: dict
        """
        return {self._case.sub(r'\1_\2', k).lower(): v
                for k, v in token.items()}

    def _parse_token(self):
        # TODO: We could also check expires_on and use to update expires_in
        if self.token.get('expires_at'):
            countdown = float(self.token['expires_at']) - time.time()
            self.token['expires_in'] = countdown
        kwargs = {}
        if self.token.get('refresh_token'):
            kwargs['auto_refresh_url'] = self.token_uri
            kwargs['auto_refresh_kwargs'] = {'client_id': self.id,
                                             'resource': self.resource}
            kwargs['token_updater'] = self._default_token_cache
        return kwargs

    def _default_token_cache(self, token):
        """Store token for future sessions.

        :param dict token: An authentication token.
        :rtype: None
        """
        self.token = token
        if keyring:
            try:
                keyring.set_password(self.cred_store, self.store_key, str(token))
            except Exception as err:
                _LOGGER.warning("Keyring cache token has failed: %s", str(err))

    def _retrieve_stored_token(self):
        """Retrieve stored token for new session.

        :raises: ValueError if no cached token found.
        :rtype: dict
        :return: Retrieved token.
        """
        token = keyring.get_password(self.cred_store, self.store_key)
        if token is None:
            raise ValueError("No stored token found.")
        self.token = ast.literal_eval(str(token))
        self.signed_session()

    def signed_session(self):
        """Create token-friendly Requests session, using auto-refresh.
        Used internally when a request is made.

        :rtype: requests_oauthlib.OAuth2Session
        :raises: TokenExpiredError if token can no longer be refreshed.
        """
        kwargs = self._parse_token()
        try:
            new_session = oauth.OAuth2Session(
                self.id,
                token=self.token,
                **kwargs)
            return new_session
        except TokenExpiredError as err:
            raise_with_traceback(Expired, "", err)

    def clear_cached_token(self):
        """Clear any stored tokens.

        :raises: KeyError if failed to clear token.
        :rtype: None
        """
        try:
            keyring.delete_password(self.cred_store, self.store_key)
        except keyring.errors.PasswordDeleteError:
            raise_with_traceback(KeyError, "Unable to clear token.")


class AADRefreshMixin(object):
    """
    Additional token refresh logic
    """

    def refresh_session(self):
        """Return updated session if token has expired, attempts to
        refresh using newly acquired token.

        :rtype: requests.Session.
        """
        if self.token.get('refresh_token'):
            try:
                return self.signed_session()
            except Expired:
                pass
        self.set_token()
        return self.signed_session()


class AADTokenCredentials(AADMixin):
    """
    Credentials objects for AAD token retrieved through external process
    e.g. Python ADAL lib.

    Optional kwargs may include:
    - cloud_environment (msrestazure.azure_cloud.Cloud): A targeted cloud environment
    - china (bool): Configure auth for China-based service,
      default is 'False'.
    - tenant (str): Alternative tenant, default is 'common'.
    - auth_uri (str): Alternative authentication endpoint.
    - token_uri (str): Alternative token retrieval endpoint.
    - resource (str): Alternative authentication resource, default
      is 'https://management.core.windows.net/'.
    - verify (bool): Verify secure connection, default is 'True'.
    - keyring (str): Name of local token cache, default is 'AzureAAD'.
    - cached (bool): If true, will not attempt to collect a token,
      which can then be populated later from a cached token.

    :param dict token: Authentication token.
    :param str client_id: Client ID, if not set, Xplat Client ID
     will be used.
    """

    def __init__(self, token, client_id=None, **kwargs):
        if not client_id:
            # Default to Xplat Client ID.
            client_id = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
        super(AADTokenCredentials, self).__init__(client_id, None)
        self._configure(**kwargs)
        if not kwargs.get('cached'):
            self.token = self._convert_token(token)
            self.signed_session()

    @classmethod
    def retrieve_session(cls, client_id=None):
        """Create AADTokenCredentials from a cached token if it has not
        yet expired.
        """
        session = cls(None, None, client_id=client_id, cached=True)
        session._retrieve_stored_token()
        return session


class UserPassCredentials(AADRefreshMixin, AADMixin):
    """Credentials object for Headless Authentication,
    i.e. AAD authentication via username and password.

    Headless Auth requires an AAD login (no a Live ID) that already has
    permission to access the resource e.g. an organization account, and
    that 2-factor auth be disabled.

    Optional kwargs may include:
    - cloud_environment (msrestazure.azure_cloud.Cloud): A targeted cloud environment
    - china (bool): Configure auth for China-based service,
      default is 'False'.
    - tenant (str): Alternative tenant, default is 'common'.
    - auth_uri (str): Alternative authentication endpoint.
    - token_uri (str): Alternative token retrieval endpoint.
    - resource (str): Alternative authentication resource, default
      is 'https://management.core.windows.net/'.
    - verify (bool): Verify secure connection, default is 'True'.
    - keyring (str): Name of local token cache, default is 'AzureAAD'.
    - timeout (int): Timeout of the request in seconds.
    - cached (bool): If true, will not attempt to collect a token,
      which can then be populated later from a cached token.
    - proxies (dict): Dictionary mapping protocol or protocol and
      hostname to the URL of the proxy.

    :param str username: Account username.
    :param str password: Account password.
    :param str client_id: Client ID, if not set, Xplat Client ID
     will be used.
    :param str secret: Client secret, only if required by server.
    """

    def __init__(self, username, password,
                 client_id=None, secret=None, **kwargs):
        if not client_id:
            # Default to Xplat Client ID.
            client_id = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
        super(UserPassCredentials, self).__init__(client_id, None)
        self._configure(**kwargs)

        self.store_key += "_{}".format(username)
        self.username = username
        self.password = password
        self.secret = secret
        self.client = LegacyApplicationClient(client_id=self.id)
        if not kwargs.get('cached'):
            self.set_token()

    @classmethod
    def retrieve_session(cls, username, client_id=None):
        """Create ServicePrincipalCredentials from a cached token if it has not
        yet expired.
        """
        session = cls(username, None, client_id=client_id, cached=True)
        session._retrieve_stored_token()
        return session

    def _setup_session(self):
        """Create token-friendly Requests session.

        :rtype: requests_oauthlib.OAuth2Session
        """
        return oauth.OAuth2Session(client=self.client)

    def set_token(self):
        """Get token using Username/Password credentials.

        :raises: AuthenticationError if credentials invalid, or call fails.
        """
        with self._setup_session() as session:
            optional = {}
            if self.secret:
                optional['client_secret'] = self.secret
            try:
                token = session.fetch_token(self.token_uri, client_id=self.id,
                                            username=self.username,
                                            password=self.password,
                                            resource=self.resource,
                                            verify=self.verify,
                                            proxies=self.proxies,
                                            timeout=self.timeout,
                                            **optional)
            except (RequestException, OAuth2Error, InvalidGrantError) as err:
                raise_with_traceback(AuthenticationError, "", err)

            self.token = token


class ServicePrincipalCredentials(AADRefreshMixin, AADMixin):
    """Credentials object for Service Principle Authentication.
    Authenticates via a Client ID and Secret.

    Optional kwargs may include:
    - cloud_environment (msrestazure.azure_cloud.Cloud): A targeted cloud environment
    - china (bool): Configure auth for China-based service,
      default is 'False'.
    - tenant (str): Alternative tenant, default is 'common'.
    - auth_uri (str): Alternative authentication endpoint.
    - token_uri (str): Alternative token retrieval endpoint.
    - resource (str): Alternative authentication resource, default
      is 'https://management.core.windows.net/'.
    - verify (bool): Verify secure connection, default is 'True'.
    - keyring (str): Name of local token cache, default is 'AzureAAD'.
    - timeout (int): Timeout of the request in seconds.
    - cached (bool): If true, will not attempt to collect a token,
      which can then be populated later from a cached token.
    - proxies (dict): Dictionary mapping protocol or protocol and
      hostname to the URL of the proxy.

    :param str client_id: Client ID.
    :param str secret: Client secret.
    """
    def __init__(self, client_id, secret, **kwargs):
        super(ServicePrincipalCredentials, self).__init__(client_id, None)
        self._configure(**kwargs)

        self.secret = secret
        self.client = BackendApplicationClient(self.id)
        if not kwargs.get('cached'):
            self.set_token()

    @classmethod
    def retrieve_session(cls, client_id):
        """Create ServicePrincipalCredentials from a cached token if it has not
        yet expired.
        """
        session = cls(client_id, None, cached=True)
        session._retrieve_stored_token()
        return session

    def _setup_session(self):
        """Create token-friendly Requests session.

        :rtype: requests_oauthlib.OAuth2Session
        """
        return oauth.OAuth2Session(self.id, client=self.client)

    def set_token(self):
        """Get token using Client ID/Secret credentials.

        :raises: AuthenticationError if credentials invalid, or call fails.
        """
        with self._setup_session() as session:
            try:
                token = session.fetch_token(self.token_uri, client_id=self.id,
                                            resource=self.resource,
                                            client_secret=self.secret,
                                            response_type="client_credentials",
                                            verify=self.verify,
                                            timeout=self.timeout,
                                            proxies=self.proxies)
            except (RequestException, OAuth2Error, InvalidGrantError) as err:
                raise_with_traceback(AuthenticationError, "", err)
            else:
                self.token = token

# For backward compatibility of import, but I doubt someone uses that...
class InteractiveCredentials(object):
    def __init__(self, *args, **kwargs):
        raise NotImplementedError("InteractiveCredentials was not functionning and was removed. Please use ADAL and device code instead.")

class AdalAuthentication(Authentication):  # pylint: disable=too-few-public-methods
    """A wrapper to use ADAL for Python easily to authenticate on Azure.

    .. versionadded:: 0.4.5
    """

    def __init__(self, adal_method, *args, **kwargs):
        """Take an ADAL `acquire_token` method and its parameters.

        :Example:

        .. code:: python

            context = adal.AuthenticationContext('https://login.microsoftonline.com/ABCDEFGH-1234-1234-1234-ABCDEFGHIJKL')
            RESOURCE = '00000002-0000-0000-c000-000000000000' #AAD graph resource
            token = context.acquire_token_with_client_credentials(
                RESOURCE,
                "http://PythonSDK",
                "Key-Configured-In-Portal")

        can be written here:

        .. code:: python

            context = adal.AuthenticationContext('https://login.microsoftonline.com/ABCDEFGH-1234-1234-1234-ABCDEFGHIJKL')
            RESOURCE = '00000002-0000-0000-c000-000000000000' #AAD graph resource
            credentials = AdalAuthentication(
                context.acquire_token_with_client_credentials,
                RESOURCE,
                "http://PythonSDK",
                "Key-Configured-In-Portal")

        or using a lambda if you prefer:

        .. code:: python

            context = adal.AuthenticationContext('https://login.microsoftonline.com/ABCDEFGH-1234-1234-1234-ABCDEFGHIJKL')
            RESOURCE = '00000002-0000-0000-c000-000000000000' #AAD graph resource
            credentials = AdalAuthentication(
                lambda: context.acquire_token_with_client_credentials(
                    RESOURCE,
                    "http://PythonSDK",
                    "Key-Configured-In-Portal"
                )
            )

        :param adal_method: A lambda with no args, or `acquire_token` method with args using args/kwargs
        :param args: Optional args for the method
        :param kwargs: Optional kwargs for the method
        """
        self._adal_method = adal_method
        self._args = args
        self._kwargs = kwargs

    def signed_session(self):
        """Get a signed session for requests.

        Usually called by the Azure SDKs for you to authenticate queries.

        :rtype: requests.Session
        """
        session = super(AdalAuthentication, self).signed_session()

        try:
            raw_token = self._adal_method(*self._args, **self._kwargs)
        except adal.AdalError as err:
            # pylint: disable=no-member
            if 'AADSTS70008:' in ((getattr(err, 'error_response', None) or {}).get('error_description') or ''):
                raise Expired("Credentials have expired due to inactivity.")
            else:
                raise AuthenticationError(err)
        except ConnectionError as err:
            raise AuthenticationError('Please ensure you have network connection. Error detail: ' + str(err))

        scheme, token = raw_token['tokenType'], raw_token['accessToken']
        header = "{} {}".format(scheme, token)
        session.headers['Authorization'] = header
        return session


def get_msi_token(resource, port=50342):
    request_uri = 'http://localhost:{}/oauth2/token'.format(port)
    payload = {
        'resource': resource
    }

    # retry as the token endpoint might not be available yet, one example is you use CLI in a
    # custom script extension of VMSS, which might get provisioned before the MSI extensioon
    while True:
        err = None
        try:
            result = requests.post(request_uri, data=payload, headers={'Metadata': 'true'})
            _LOGGER.debug("MSI: Retrieving a token from %s, with payload %s", request_uri, payload)
            if result.status_code != 200:
                err = result.text
        except Exception as ex:  # pylint: disable=broad-except
            err = str(ex)

        if err:
            # we might need some error code checking to avoid silly waiting. The bottom line is users can
            # always press ctrl+c to stop it
            _LOGGER.warning("MSI: Failed to retrieve a token from '%s' with an error of '%s'. This could be caused "
                            "by the MSI extension not yet fullly provisioned. Will retry in 60 seconds...",
                            request_uri, err)
            time.sleep(60)
        else:
            _LOGGER.debug('MSI: token retrieved')
            break
    token_entry = result.json()
    return token_entry['token_type'], token_entry['access_token'], token_entry

def get_msi_token_webapp(resource):
    """Get a MSI token from inside a webapp or functions.

    Env variable will look like:
    MSI_ENDPOINT = http://127.0.0.1:41741/MSI/token/
    MSI_SECRET = 69418689F1E342DD946CB82994CDA3CB
    """
    try:
        msi_endpoint = os.environ['MSI_ENDPOINT']
        msi_secret = os.environ['MSI_SECRET']
    except KeyError as err:
        err_msg = "{} required env variable was not found. You might need to restart your app/function.".format(err)
        _LOGGER.critical(err_msg)
        raise RuntimeError(err_msg)
    request_uri = '{}/?resource={}&api-version=2017-09-01'.format(msi_endpoint, resource)
    headers = {
        'secret': msi_secret
    }

    err = None
    try:
        result = requests.get(request_uri, headers=headers)
        _LOGGER.debug("MSI: Retrieving a token from %s", request_uri)
        if result.status_code != 200:
            err = result.text
        # Workaround since not all failures are != 200
        if 'ExceptionMessage' in result.text:
            err = result.text
    except Exception as ex:  # pylint: disable=broad-except
        err = str(ex)

    if err:
        err_msg = "MSI: Failed to retrieve a token from '{}' with an error of '{}'.".format(
            request_uri, err
        )
        _LOGGER.critical(err_msg)
        raise RuntimeError(err_msg)
    _LOGGER.debug('MSI: token retrieved')
    token_entry = result.json()
    return token_entry['token_type'], token_entry['access_token'], token_entry


class MSIAuthentication(BasicTokenAuthentication):
    """Credentials object for MSI authentication,.

    Optional kwargs may include:
    - cloud_environment (msrestazure.azure_cloud.Cloud): A targeted cloud environment
    - resource (str): Alternative authentication resource, default
      is 'https://management.core.windows.net/'.

    :param int port: MSI local port if VM/VMSS context (ignored otherwise)
    """

    def __init__(self, port=50342, **kwargs):
        super(MSIAuthentication, self).__init__(None)

        self.port = port

        self.cloud_environment = kwargs.get('cloud_environment', AZURE_PUBLIC_CLOUD)
        self.resource = kwargs.get('resource', self.cloud_environment.endpoints.management)

    def set_token(self):
        if 'MSI_ENDPOINT' in os.environ:
            self.scheme, _, self.token = get_msi_token_webapp(self.resource)
        else:
            self.scheme, _, self.token = get_msi_token(self.resource, self.port)

    def signed_session(self):
        # Token cache is handled by the VM extension, call each time to avoid expiration
        self.set_token()
        return super(MSIAuthentication, self).signed_session()
