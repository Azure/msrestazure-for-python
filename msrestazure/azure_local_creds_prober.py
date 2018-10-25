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


import os
import json
import platform
import logging
from subprocess import PIPE, Popen
import requests
from msrest.authentication import BasicTokenAuthentication
from msrestazure.azure_active_directory import MSIAuthentication, ServicePrincipalCredentials

_LOGGER = logging.getLogger(__name__)

#pylint: disable=too-few-public-methods,missing-docstring

class CredsProber:

    def __init__(self, resource):
        self.enabled = True
        self.resource = resource


class ManagedServiceIdentityProber(CredsProber):

    def probe(self, subscription_id=None):
        if not self.enabled:
            return None
        try:
            creds = MSIAuthentication()
            _LOGGER.warning('Managed system identity was detected')
            return creds, subscription_id or _get_subscription_id(creds)
        except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError):
            return None, None


class ConnectionStrEnvProber(CredsProber):
    '''
    Detect environment variable AZURE_CONN_STR
    '''
    def probe(self, subscription_id=None):
        creds = None
        if self.enabled and os.environ.get('AZURE_CONN_STR'):
            auth_info = json.loads(os.environ.get('AZURE_CONN_STR'))
            creds = ServicePrincipalCredentials(client_id=auth_info['clientId'],
                                                secret=auth_info['clientSecret'],
                                                tennt_id=auth_info['tenantId'])
            return creds, (subscription_id or auth_info.get('subscriptionId') or
                           _get_subscription_id(creds))
        return None, None


class ServicePrincipalEnvProber(CredsProber):
    '''
    Detect envrionment variable AZURE_CLIENT_ID, AZURE_CLIENT_SECRET and AZURE_TENANT_ID
    '''
    def probe(self, subscription_id=None):
        creds = None
        if os.environ.get('AZURE_CLIENT_ID'):
            client_id, client_secret, tenant_id = (os.environ.get('AZURE_CLIENT_ID'),
                                                   os.environ.get('AZURE_CLIENT_SECRET'),
                                                   os.environ.get('AZURE_TENANT_ID'))
            if not client_secret or not tenant_id:
                raise ValueError('Environment variables of AZURE_CLIENT_SECRET and'
                                 ' AZURE_TENANT_ID must be set')
            creds = ServicePrincipalCredentials(client_id=client_id, secret=client_secret,
                                                tenant=tenant_id, resource=self.resource)

            _LOGGER.warning('Service principal credentials was detected')
            return creds, (subscription_id or os.environ.get('AZURE_SUBSCRIPTION_ID') or
                           _get_subscription_id(creds))
        return None, None


class AzureCLIProber(CredsProber):
    '''
    Detect CLI installations
    '''
    def probe(self, subscription_id=None):  # pylint: disable=no-self-use
        uname = platform.uname()
        platform_name = getattr(uname, 'system', None) or uname[0]
        platform_name = platform_name.lower()
        if platform_name == 'windows':
            program_files_folder = (os.environ.get('ProgramFiles(x86)') or
                                    os.environ.get('ProgramFiles'))
            probing_path = os.path.join(program_files_folder, 'Microsoft SDKs',
                                        'Azure', 'CLI2', 'wbin', 'az.cmd')
            if os.path.isfile(probing_path):
                cli_path = probing_path
        else:
            import shutil
            try:
                cli_path = shutil.which('az')
            except AttributeError:
                process = Popen(['which', 'az'], stdout=PIPE, stderr=PIPE)
                stdout, stderr = process.communicate()
                process.wait()
                if not stderr:
                    installed_clis = [s.trim() for s in stdout.split('\n') if s]
                    cli_path = installed_clis[0]
                    if len(installed_clis) > 1:
                        _LOGGER.warning('More than one Azure CLI are installed at "%s"'
                                        ' Pick the 1st one.', ', '.join(installed_clis))

        if cli_path:
            creds = CLICredentials(cli_path)
            if subscription_id is None:
                creds.set_token()
                subscription_id = creds.subscription_id
            return creds, subscription_id
        return None, None


class CLICredentials(BasicTokenAuthentication):

    def __init__(self, cli_path, subscription_id=None):
        super(CLICredentials, self).__init__(None)
        self.cli_path = cli_path
        self.subscription_id = subscription_id
        self.expires_on = None

    def set_token(self):
        from dateutil import parser
        from datetime import timedelta, datetime
        if (not self.token or self.expires_on and
                (datetime.now() + timedelta(minutes=5)) > self.expires_on):
            info = self._invoke_cli_token_command()
            self.scheme, self.token, self.expires_on = (info['tokenType'],
                                                        {'access_token': info['accessToken']},
                                                        parser.parse(info['expiresOn']))
            if self.subscription_id is None:
                self.subscription_id = info['subscription']
        return self.scheme, self.token

    def _invoke_cli_token_command(self):
        args = [self.cli_path, 'account', 'get-access-token']
        if self.subscription_id:
            args.extend(['--subscription', self.subscription_id])
        process = Popen(args, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        process.wait()
        if stderr:
            raise ValueError('Retrieving acccess token failed: ' + stderr)
        return json.loads(stdout)

    def signed_session(self, session=None):
        self.set_token()
        return super(CLICredentials, self).signed_session(session)

def _get_subscription_id(creds):
    subscription_id = None
    try:
        from azure.mgmt.resource.subscriptions import SubscriptionClient
        subscriptions = list(SubscriptionClient(creds).subscriptions.list())
        if subscriptions:
            subscription_ids = [s.id.split('/')[-1] for s in subscriptions]
            subscription_id = subscription_ids[0]
            _LOGGER.warning('Found subscription "%s" to use', subscription_ids[0])
            if len(subscription_ids) > 1:
                _LOGGER.warning('You also have accesses to a few other subscriptions "%S".'
                                ' You can supply subscription_id on creating the probe object')
    except ImportError:  # should be rare
        _LOGGER.warning('Failed to load azure.mgmt.resource.subscriptions to find the default'
                        ' subscription. If this is expected, supply subscription_id on creating'
                        ' the probe object')
    return subscription_id


def get_client_through_local_creds_probing(client_class, **kwargs):
    '''
    Probing logics:
    1. AZURE_CONN_STR, with SDK auth code file content in json.
        https://github.com/Azure/azure-sdk-for-java/wiki/Authentication
    2. Individual environment variables to estabslish a service principal's creds
        https://github.com/Azure/azure-sdk-for-go
    3. Managed service identity
        a. app service
        b. virtual machine
    4. Azure CLI, through "az account get-access-token"
    '''
    resource = kwargs.get('resource')
    if not resource:
        from .azure_cloud import AZURE_PUBLIC_CLOUD
        resource = AZURE_PUBLIC_CLOUD.endpoints.resource_manager
    probers = [ConnectionStrEnvProber(resource), ServicePrincipalEnvProber(resource),
               ManagedServiceIdentityProber(resource), AzureCLIProber(resource)]
    for prober in probers:
        creds, subscription_id = prober.probe(subscription_id=kwargs.get('subscription_id'))
        if creds:
            return client_class(creds, subscription_id)
    raise ValueError('No credential was detected from the local machine')
