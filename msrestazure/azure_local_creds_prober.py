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

class CLICredentials(BasicTokenAuthentication):

    def __init__(self, resource=None, subscription_id=None):   # allow subscriptions
        super(CLICredentials, self).__init__(None)
        uname = platform.uname()
        # python 2, `platform.uname()` returns: tuple(system, node, release, version, machine, processor)
        platform_name = getattr(uname, 'system', None) or uname[0]
        platform_name = platform_name.lower()
        if platform_name == 'windows':
            program_files_folder = os.environ.get('ProgramFiles(x86)') or os.environ.get('ProgramFiles')
            probing_paths = [os.path.join(program_files_folder, 'Microsoft SDKs', 'Azure', 'CLI2', 'wbin', 'az.cmd')]
        else:
            probing_paths = ['/usr/bin/az', '/usr/local/bin/az']
        
        cli_path = next((p for p in probing_paths if os.path.isfile(p)), None)
        if cli_path is None:
            raise NotImplementedError('Azure CLI is not installed')
        self.cli_path = cli_path
        self.resource = resource
        self.subscription_id = subscription_id
        self.token = None

    def set_token(self):
        args = [self.cli_path, 'account', 'get-access-token']
        if self.subscription_id:
            args.extend(['--subscription', self.subscription_id])
        p = Popen(args, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        p.wait()
        if stderr:
            raise ValueError('Retrieving acccess token failed: ' + stderr)
        info = json.loads(stdout)
        self.scheme, self.token = info['tokenType'], {'access_token': info['accessToken']}

    def signed_session(self, session=None):
        # Token cache is handled by the VM extension, call each time to avoid expiration
        self.set_token()
        return super(CLICredentials, self).signed_session(session)


class AzureLocalCredentialProber(object):

    def __init__(self, subscription_id=None):
        self.subscription_id = subscription_id
        self.creds = None
        self._probe()

    def signed_session(self, session=None):
        self.creds.signed_session(session)

    def _probe(self):
        subscription_id = self.subscription_id or os.environ.get('AZURE_SUBSCRIPTION_ID')
        try:
            creds = MSIAuthentication()
            _LOGGER.warning('Managed system identity was detected')
        except requests.exceptions.ConnectionError:
            client_id = os.environ.get('AZURE_CLIENT_ID')
            if client_id:
                creds = ServicePrincipalCredentials(client_id=client_id,
                                                    secret=os.environ.get('AZURE_CLIENT_SECRET'),
                                                    tennt_id=os.environ.get('AZURE_TENANT_ID'))
                _LOGGER.warning('Service principal credentials was detected')
            else:
                try:
                    creds = CLICredentials()
                    _LOGGER.warning('Azure CLI credentials was detected')
                except NotImplementedError:
                    raise ValueError('No credential was detected from the local machine')
        self.creds = creds
        if not subscription_id:
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
                _LOGGER.warning('Failed to load azure.mgmt.resource.subscriptions to find the default subscription.'
                                ' If this is expected, supply subscription_id on creating the probe object')
        self.subscription_id = subscription_id
