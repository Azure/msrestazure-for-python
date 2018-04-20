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
import re
import unittest
from functools import partial
try:
    from unittest import mock
except ImportError:
    import mock

from requests import Request, Response

from msrest import Deserializer
from msrest.exceptions import RequestException, DeserializationError
from msrestazure.azure_exceptions import CloudError
from msrestazure.azure_operation import (
    LongRunningOperation,
    BadStatus,
    SimpleResource)

# Don't do the critical async import for Py2.7.
# Entire class will be skipped anyway
try:
    import asyncio
    from msrestazure.azure_async_operation import AzureOperationPoller
except ImportError:
    pass

class BadEndpointError(Exception):
    pass

TEST_NAME = 'foo'
RESPONSE_BODY = {'properties':{'provisioningState': 'InProgress'}}
ASYNC_BODY = json.dumps({ 'status': 'Succeeded' })
ASYNC_URL = 'http://dummyurlFromAzureAsyncOPHeader_Return200'
LOCATION_BODY = json.dumps({ 'name': TEST_NAME })
LOCATION_URL = 'http://dummyurlurlFromLocationHeader_Return200'
RESOURCE_BODY = json.dumps({ 'name': TEST_NAME })
RESOURCE_URL = 'http://subscriptions/sub1/resourcegroups/g1/resourcetype1/resource1'
ERROR = 'http://dummyurl_ReturnError'
POLLING_STATUS = 200

@unittest.skipIf(sys.version_info < (3,4), "Asyncio tests")
class TestLongRunningOperation(unittest.TestCase):

    convert = re.compile('([a-z0-9])([A-Z])')

    def setUp(self):
        self.loop = asyncio.get_event_loop()
        return super(TestLongRunningOperation, self).setUp()

    @staticmethod
    def mock_send(method, status, headers, body=None):
        response = mock.create_autospec(Response)
        response.request = mock.create_autospec(Request)
        response.request.method = method
        response.request.url = RESOURCE_URL
        response.status_code = status
        response.headers = headers
        content = body if body else RESPONSE_BODY
        response.content = json.dumps(content)
        response.json = lambda: json.loads(response.content)
        return lambda: response

    @staticmethod
    def mock_update_with_ref(url, headers=None, ref_result=None):
        response = mock.create_autospec(Response)
        response.request = mock.create_autospec(Request)
        response.request.method = 'GET'
        response.headers = headers or {}
        
        if url == ASYNC_URL:
            response.request.url = url
            response.status_code = POLLING_STATUS
            response.content = ASYNC_BODY
            response.randomFieldFromPollAsyncOpHeader = None

        elif url == LOCATION_URL:
            response.request.url = url
            response.status_code = POLLING_STATUS
            response.content = LOCATION_BODY
            response.randomFieldFromPollLocationHeader = None

        elif url == ERROR:
            raise BadEndpointError("boom")

        elif url == RESOURCE_URL:
            response.request.url = url
            response.status_code = POLLING_STATUS
            response.content = RESOURCE_BODY

        else:
            raise Exception('URL does not match')
        response.json = lambda: json.loads(response.content)
        if ref_result is not None:
            ref_result["response"] = response
        return response

    @staticmethod
    def mock_outputs(response):
        body = response.json()
        body = {TestLongRunningOperation.convert.sub(r'\1_\2', k).lower(): v 
                for k, v in body.items()}
        properties = body.setdefault('properties', {})
        if 'name' in body:
            properties['name'] = body['name']
        if properties:
            properties = {TestLongRunningOperation.convert.sub(r'\1_\2', k).lower(): v 
                          for k, v in properties.items()}
            del body['properties']
            body.update(properties)
            resource = SimpleResource(**body)
        else:
            raise DeserializationError("Impossible to deserialize")
            resource = SimpleResource(**body)
        return resource

    def test_long_running_put(self):
        #TODO: Test custom header field

        # Test throw on non LRO related status code
        response = TestLongRunningOperation.mock_send('PUT', 1000, {})
        op = LongRunningOperation(response(), lambda x:None)
        with self.assertRaises(BadStatus):
            op.set_initial_status(response())
        with self.assertRaises(CloudError):
            poll = AzureOperationPoller(response,
                TestLongRunningOperation.mock_outputs,
                TestLongRunningOperation.mock_update_with_ref, 0)
            self.loop.run_until_complete(poll)

        # Test with no polling necessary
        response_body = {
            'properties':{'provisioningState': 'Succeeded'},
            'name': TEST_NAME
        }
        response = TestLongRunningOperation.mock_send(
            'PUT', 201,
            {}, response_body
        )
        def no_update_allowed(url, headers=None):
            raise ValueError("Should not try to update")
        poll = AzureOperationPoller(response,
            TestLongRunningOperation.mock_outputs,
            no_update_allowed,
            0
        )
        result = self.loop.run_until_complete(poll)
        self.assertEqual(result.name, TEST_NAME)

        # Test polling from azure-asyncoperation header
        response = TestLongRunningOperation.mock_send(
            'PUT', 201,
            {'azure-asyncoperation': ASYNC_URL})
        ref_result = {}
        local_mock_update = partial(TestLongRunningOperation.mock_update_with_ref,
                                    ref_result=ref_result)
        poll = AzureOperationPoller(response,
            TestLongRunningOperation.mock_outputs,
            local_mock_update, 0)
        result = self.loop.run_until_complete(poll)
        self.assertEqual(result.name, TEST_NAME)
        self.assertFalse(hasattr(ref_result["response"], 'randomFieldFromPollAsyncOpHeader'))

        # Test polling location header
        response = TestLongRunningOperation.mock_send(
            'PUT', 201,
            {'location': LOCATION_URL})
        ref_result = {}
        local_mock_update = partial(TestLongRunningOperation.mock_update_with_ref,
                                    ref_result=ref_result)            
        poll = AzureOperationPoller(response,
            TestLongRunningOperation.mock_outputs,
            local_mock_update, 0)
        result = self.loop.run_until_complete(poll)
        self.assertEqual(result.name, TEST_NAME)
        self.assertIsNone(ref_result["response"].randomFieldFromPollLocationHeader)

        # Test polling initial payload invalid (SQLDb)
        response_body = {}  # Empty will raise
        response = TestLongRunningOperation.mock_send(
            'PUT', 201,
            {'location': LOCATION_URL}, response_body)
        ref_result = {}
        local_mock_update = partial(TestLongRunningOperation.mock_update_with_ref,
                                    ref_result=ref_result)            
        poll = AzureOperationPoller(response,
            TestLongRunningOperation.mock_outputs,
            local_mock_update, 0)
        result = self.loop.run_until_complete(poll)
        self.assertEqual(result.name, TEST_NAME)
        self.assertIsNone(ref_result["response"].randomFieldFromPollLocationHeader)

        # Test fail to poll from azure-asyncoperation header
        response = TestLongRunningOperation.mock_send(
            'PUT', 201,
            {'azure-asyncoperation': ERROR})
        with self.assertRaises(BadEndpointError):
            poll = AzureOperationPoller(response,
                TestLongRunningOperation.mock_outputs,
                TestLongRunningOperation.mock_update_with_ref, 0)
            self.loop.run_until_complete(poll)

        # Test fail to poll from location header
        response = TestLongRunningOperation.mock_send(
            'PUT', 201,
            {'location': ERROR})
        with self.assertRaises(BadEndpointError):
            poll = AzureOperationPoller(response,
                TestLongRunningOperation.mock_outputs,
                TestLongRunningOperation.mock_update_with_ref, 0)
            self.loop.run_until_complete(poll)

    def test_long_running_patch(self):

        # Test polling from location header
        response = TestLongRunningOperation.mock_send(
            'PATCH', 202,
            {'location': LOCATION_URL},
            body={'properties':{'provisioningState': 'Succeeded'}})
        ref_result = {}
        local_mock_update = partial(TestLongRunningOperation.mock_update_with_ref,
                                    ref_result=ref_result)            
        poll = AzureOperationPoller(response,
            TestLongRunningOperation.mock_outputs,
            local_mock_update, 0)
        result = self.loop.run_until_complete(poll)
        self.assertEqual(result.name, TEST_NAME)
        self.assertIsNone(ref_result["response"].randomFieldFromPollLocationHeader)

        # Test polling from azure-asyncoperation header
        response = TestLongRunningOperation.mock_send(
            'PATCH', 202,
            {'azure-asyncoperation': ASYNC_URL},
            body={'properties':{'provisioningState': 'Succeeded'}})
        ref_result = {}
        local_mock_update = partial(TestLongRunningOperation.mock_update_with_ref,
                                    ref_result=ref_result)            
        poll = AzureOperationPoller(response,
            TestLongRunningOperation.mock_outputs,
            local_mock_update, 0)
        result = self.loop.run_until_complete(poll)
        self.assertEqual(result.name, TEST_NAME)
        self.assertFalse(hasattr(ref_result["response"], 'randomFieldFromPollAsyncOpHeader'))

        # Test polling from location header
        response = TestLongRunningOperation.mock_send(
            'PATCH', 200,
            {'location': LOCATION_URL},
            body={'properties':{'provisioningState': 'Succeeded'}})
        ref_result = {}
        local_mock_update = partial(TestLongRunningOperation.mock_update_with_ref,
                                    ref_result=ref_result)            
        poll = AzureOperationPoller(response,
            TestLongRunningOperation.mock_outputs,
            local_mock_update, 0)
        result = self.loop.run_until_complete(poll)
        self.assertEqual(result.name, TEST_NAME)
        self.assertIsNone(ref_result["response"].randomFieldFromPollLocationHeader)

        # Test polling from azure-asyncoperation header
        response = TestLongRunningOperation.mock_send(
            'PATCH', 200,
            {'azure-asyncoperation': ASYNC_URL},
            body={'properties':{'provisioningState': 'Succeeded'}})
        ref_result = {}
        local_mock_update = partial(TestLongRunningOperation.mock_update_with_ref,
                                    ref_result=ref_result)            
        poll = AzureOperationPoller(response,
            TestLongRunningOperation.mock_outputs,
            local_mock_update, 0)
        result = self.loop.run_until_complete(poll)
        self.assertEqual(result.name, TEST_NAME)
        self.assertFalse(hasattr(ref_result["response"], 'randomFieldFromPollAsyncOpHeader'))

        # Test fail to poll from azure-asyncoperation header
        response = TestLongRunningOperation.mock_send(
            'PATCH', 202,
            {'azure-asyncoperation': ERROR})
        with self.assertRaises(BadEndpointError):
            poll = AzureOperationPoller(response,
                TestLongRunningOperation.mock_outputs,
                TestLongRunningOperation.mock_update_with_ref, 0)
            self.loop.run_until_complete(poll)

        # Test fail to poll from location header
        response = TestLongRunningOperation.mock_send(
            'PATCH', 202,
            {'location': ERROR})
        with self.assertRaises(BadEndpointError):
            poll = AzureOperationPoller(response,
                TestLongRunningOperation.mock_outputs,
                TestLongRunningOperation.mock_update_with_ref, 0)
            self.loop.run_until_complete(poll)

    def test_long_running_delete(self):
        # Test polling from azure-asyncoperation header
        response = TestLongRunningOperation.mock_send(
            'DELETE', 202,
            {'azure-asyncoperation': ASYNC_URL})
        ref_result = {}
        local_mock_update = partial(TestLongRunningOperation.mock_update_with_ref,
                                    ref_result=ref_result)            
        poll = AzureOperationPoller(response,
            TestLongRunningOperation.mock_outputs,
            local_mock_update, 0)
        result = self.loop.run_until_complete(poll)
        self.assertIsNone(result)
        self.assertIsNone(ref_result["response"].randomFieldFromPollAsyncOpHeader)

    def test_long_running_post(self):

        # Test throw on non LRO related status code
        response = TestLongRunningOperation.mock_send('POST', 201, {})
        op = LongRunningOperation(response(), lambda x:None)
        with self.assertRaises(BadStatus):
            op.set_initial_status(response())
        with self.assertRaises(CloudError):
            poll = AzureOperationPoller(response,
                TestLongRunningOperation.mock_outputs,
                TestLongRunningOperation.mock_update_with_ref, 0)
            self.loop.run_until_complete(poll)

        # Test polling from azure-asyncoperation header
        response = TestLongRunningOperation.mock_send(
            'POST', 202,
            {'azure-asyncoperation': ASYNC_URL},
            body={'properties':{'provisioningState': 'Succeeded'}})
        ref_result = {}
        local_mock_update = partial(TestLongRunningOperation.mock_update_with_ref,
                                    ref_result=ref_result)            
        poll = AzureOperationPoller(response,
            TestLongRunningOperation.mock_outputs,
            local_mock_update, 0)
        result = self.loop.run_until_complete(poll)
        #self.assertIsNone(result)
        self.assertIsNone(ref_result["response"].randomFieldFromPollAsyncOpHeader)

        # Test polling from location header
        response = TestLongRunningOperation.mock_send(
            'POST', 202,
            {'location': LOCATION_URL},
            body={'properties':{'provisioningState': 'Succeeded'}})
        ref_result = {}
        local_mock_update = partial(TestLongRunningOperation.mock_update_with_ref,
                                    ref_result=ref_result)            
        poll = AzureOperationPoller(response,
            TestLongRunningOperation.mock_outputs,
            local_mock_update, 0)
        result = self.loop.run_until_complete(poll)
        self.assertEqual(result.name, TEST_NAME)
        self.assertIsNone(ref_result["response"].randomFieldFromPollLocationHeader)

        # Test fail to poll from azure-asyncoperation header
        response = TestLongRunningOperation.mock_send(
            'POST', 202,
            {'azure-asyncoperation': ERROR})
        with self.assertRaises(BadEndpointError):
            poll = AzureOperationPoller(response,
                TestLongRunningOperation.mock_outputs,
                TestLongRunningOperation.mock_update_with_ref, 0)
            self.loop.run_until_complete(poll)

        # Test fail to poll from location header
        response = TestLongRunningOperation.mock_send(
            'POST', 202,
            {'location': ERROR})
        with self.assertRaises(BadEndpointError):
            poll = AzureOperationPoller(response,
                TestLongRunningOperation.mock_outputs,
                TestLongRunningOperation.mock_update_with_ref, 0)
            self.loop.run_until_complete(poll)

    def test_long_running_negative(self):
        global LOCATION_BODY
        global POLLING_STATUS

        # Test LRO PUT throws for invalid json
        LOCATION_BODY = '{'
        response = TestLongRunningOperation.mock_send(
            'POST', 202,
            {'location': LOCATION_URL})
        poll = AzureOperationPoller(response,
            TestLongRunningOperation.mock_outputs,
            TestLongRunningOperation.mock_update_with_ref, 0)
        with self.assertRaises(DeserializationError):
            self.loop.run_until_complete(poll)

        LOCATION_BODY = '{\'"}'
        response = TestLongRunningOperation.mock_send(
            'POST', 202,
            {'location': LOCATION_URL})
        poll = AzureOperationPoller(response,
            TestLongRunningOperation.mock_outputs,
            TestLongRunningOperation.mock_update_with_ref, 0)
        with self.assertRaises(DeserializationError):
            self.loop.run_until_complete(poll)

        LOCATION_BODY = '{'
        POLLING_STATUS = 203
        response = TestLongRunningOperation.mock_send(
            'POST', 202,
            {'location': LOCATION_URL})
        poll = AzureOperationPoller(response,
            TestLongRunningOperation.mock_outputs,
            TestLongRunningOperation.mock_update_with_ref, 0)
        with self.assertRaises(CloudError): # TODO: Node.js raises on deserialization
            self.loop.run_until_complete(poll)

        LOCATION_BODY = json.dumps({ 'name': TEST_NAME })
        POLLING_STATUS = 200
        


if __name__ == '__main__':
    unittest.main()
