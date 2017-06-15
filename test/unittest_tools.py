#--------------------------------------------------------------------------
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

import unittest
import json
try:
    from unittest import mock
except ImportError:
    import mock

import requests
import httpretty

from msrestazure.azure_configuration import AzureConfiguration

class TestTools(unittest.TestCase):

    @httpretty.activate
    @mock.patch('time.sleep', return_value=None)
    def test_register_rp_hook(self, time_sleep):
        """Protocol:
        - We call the provider and get a 409 provider error
        - Now we POST register provider and get "Registering"
        - Now we GET register provider and get "Registered"
        - We call again the first endpoint and this time this succeed
        """

        provider_url = ("https://management.azure.com/"
                        "subscriptions/00000000-0000-0000-0000-000000000000/"
                        "resourceGroups/clitest.rg000001/"
                        "providers/Microsoft.Sql/servers/ygserver123?api-version=2014-04-01")

        provider_error = ('{"error":{"code":"MissingSubscriptionRegistration", '
                          '"message":"The subscription registration is in \'Unregistered\' state. '
                          'The subscription must be registered to use namespace \'Microsoft.Sql\'. '
                          'See https://aka.ms/rps-not-found for how to register subscriptions."}}')

        provider_success = '{"success": true}'

        httpretty.register_uri(httpretty.PUT,
                               provider_url,
                               responses=[
                                   httpretty.Response(body=provider_error, status=409),
                                   httpretty.Response(body=provider_success),
                               ],
                               content_type="application/json")

        register_url = ("https://management.azure.com/"
                        "subscriptions/00000000-0000-0000-0000-000000000000/"
                        "providers/Microsoft.Sql/register?api-version=2016-02-01")

        register_post_result = {
            "registrationState":"Registering"
        }
        register_get_result = {
            "registrationState":"Registered"
        }

        httpretty.register_uri(httpretty.POST,
                               register_url,
                               body=json.dumps(register_post_result),
                               content_type="application/json")

        httpretty.register_uri(httpretty.GET,
                               register_url,
                               body=json.dumps(register_get_result),
                               content_type="application/json")

        configuration = AzureConfiguration(None)
        register_rp_hook = configuration.hooks[0]

        session = requests.Session()
        def rp_cb(r, *args, **kwargs):
            kwargs.setdefault("msrest", {})["session"] = session
            return register_rp_hook(r, *args, **kwargs)
        session.hooks['response'].append(rp_cb)

        response = session.put(provider_url)
        self.assertTrue(response.json()['success'])
