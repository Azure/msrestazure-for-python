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

import re
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

from msrest.exceptions import DeserializationError, ClientException
from msrestazure.azure_exceptions import CloudError

from msrestazure import ASYNC_PROTOTYPE

FINISHED = frozenset(['succeeded', 'canceled', 'failed'])
FAILED = frozenset(['canceled', 'failed'])
SUCCEEDED = frozenset(['succeeded'])


def finished(status):
    if hasattr(status, 'value'):
        status = status.value
    return str(status).lower() in FINISHED


def failed(status):
    if hasattr(status, 'value'):
        status = status.value
    return str(status).lower() in FAILED


def succeeded(status):
    if hasattr(status, 'value'):
        status = status.value
    return str(status).lower() in SUCCEEDED


def _validate(url):
    """Validate a url.

    :param str url: Polling URL extracted from response header.
    :raises: ValueError if URL has no scheme or host.
    """
    if url is None:
        return
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Invalid URL header")

def _get_header_url(response, header_name):
    """Get a URL from a header requests.

    :param requests.Response response: REST call response.
    :param str header_name: Header name.
    :returns: URL if not None AND valid, None otherwise
    """
    url = response.headers.get(header_name)
    try:
        _validate(url)
    except ValueError:
        return None
    else:
        return url

class BadStatus(Exception):
    pass


class BadResponse(Exception):
    pass


class OperationFailed(Exception):
    pass


class SimpleResource:
    """An implementation of Python 3 SimpleNamespace.
    Used to deserialize resource objects from response bodies where
    no particular object type has been specified.
    """

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        keys = sorted(self.__dict__)
        items = ("{}={!r}".format(k, self.__dict__[k]) for k in keys)
        return "{}({})".format(type(self).__name__, ", ".join(items))

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


class LongRunningOperation(object):
    """LongRunningOperation
    Provides default logic for interpreting operation responses
    and status updates.
    """
    _convert = re.compile('([a-z0-9])([A-Z])')

    def __init__(self, response, outputs):
        self.method = response.request.method
        self.status = ""
        self.resource = None
        self.get_outputs = outputs
        self.async_url = None
        self.location_url = None
        self.initial_status_code = None

    def _raise_if_bad_http_status_and_method(self, response):
        """Check response status code is valid for a Put or Patch
        request. Must be 200, 201, 202, or 204.

        :raises: BadStatus if invalid status.
        """
        code = response.status_code
        if code in {200, 202} or \
           (code == 201 and self.method in {'PUT', 'PATCH'}) or \
           (code == 204 and self.method in {'DELETE', 'POST'}):
            return
        raise BadStatus(
            "Invalid return status for {!r} operation".format(self.method))

    def _is_empty(self, response):
        """Check if response body contains meaningful content.

        :rtype: bool
        :raises: DeserializationError if response body contains invalid
         json data.
        """
        if not response.content:
            return True
        try:
            body = response.json()
            return not body
        except ValueError:
            raise DeserializationError(
                "Error occurred in deserializing the response body.")

    def _deserialize(self, response):
        """Attempt to deserialize resource from response.

        :param requests.Response response: latest REST call response.
        """
        # Hacking response with initial status_code
        previous_status = response.status_code
        response.status_code = self.initial_status_code
        resource = self.get_outputs(response)
        response.status_code = previous_status

        # Hack for Storage or SQL, to workaround the bug in the Python generator
        if resource is None:
            previous_status = response.status_code
            for status_code_to_test in [200, 201]:
                try:
                    response.status_code = status_code_to_test
                    resource = self.get_outputs(response)
                except ClientException:
                    pass
                else:
                    return resource
                finally:
                    response.status_code = previous_status
        return resource

    def _get_async_status(self, response):
        """Attempt to find status info in response body.

        :param requests.Response response: latest REST call response.
        :rtype: str
        :returns: Status if found, else 'None'.
        """
        if self._is_empty(response):
            return None
        body = response.json()
        return body.get('status')

    def _get_provisioning_state(self, response):
        """
        Attempt to get provisioning state from resource.
        :param requests.Response response: latest REST call response.
        :returns: Status if found, else 'None'.
        """
        if self._is_empty(response):
            return None
        body = response.json()
        return body.get("properties", {}).get("provisioningState")

    def should_do_final_get(self):
        """Check whether the polling should end doing a final GET.

        :param requests.Response response: latest REST call response.
        :rtype: bool
        """
        return (self.async_url or not self.resource) and \
                self.method in {'PUT', 'PATCH'}

    def set_initial_status(self, response):
        """Process first response after initiating long running
        operation and set self.status attribute.

        :param requests.Response response: initial REST call response.
        """
        self._raise_if_bad_http_status_and_method(response)

        if self._is_empty(response):
            self.resource = None
        else:
            try:
                self.resource = self.get_outputs(response)
            except DeserializationError:
                self.resource = None

        self.set_async_url_if_present(response)

        if response.status_code in {200, 201, 202, 204}:
            self.initial_status_code = response.status_code
            if self.async_url or self.location_url or response.status_code == 202:
                self.status = 'InProgress'
            elif response.status_code == 201:
                status = self._get_provisioning_state(response)
                self.status = status or 'InProgress'
            elif response.status_code == 200:
                status = self._get_provisioning_state(response)
                self.status = status or 'Succeeded'
            elif response.status_code == 204:
                self.status = 'Succeeded'
                self.resource = None
            else:
                raise OperationFailed("Invalid status found")
            return
        raise OperationFailed("Operation failed or cancelled")

    def get_status_from_location(self, response):
        """Process the latest status update retrieved from a 'location'
        header.

        :param requests.Response response: latest REST call response.
        :raises: BadResponse if response has no body and not status 202.
        """
        self._raise_if_bad_http_status_and_method(response)
        code = response.status_code
        if code == 202:
            self.status = "InProgress"
        else:
            self.status = 'Succeeded'
            if self._is_empty(response):
                self.resource = None
            else:
                self.resource = self._deserialize(response)

    def get_status_from_resource(self, response):
        """Process the latest status update retrieved from the same URL as
        the previous request.

        :param requests.Response response: latest REST call response.
        :raises: BadResponse if status not 200 or 204.
        """
        self._raise_if_bad_http_status_and_method(response)
        if self._is_empty(response):
            raise BadResponse('The response from long running operation '
                              'does not contain a body.')

        status = self._get_provisioning_state(response)
        self.status = status or 'Succeeded'

        self.resource = self._deserialize(response)

    def get_status_from_async(self, response):
        """Process the latest status update retrieved from a
        'azure-asyncoperation' header.

        :param requests.Response response: latest REST call response.
        :raises: BadResponse if response has no body, or body does not
         contain status.
        """
        self._raise_if_bad_http_status_and_method(response)
        if self._is_empty(response):
            raise BadResponse('The response from long running operation '
                              'does not contain a body.')

        self.status = self._get_async_status(response)
        if not self.status:
            raise BadResponse("No status found in body")

        # Status can contains information, see ARM spec:
        # https://github.com/Azure/azure-resource-manager-rpc/blob/master/v1.0/Addendum.md#operation-resource-format
        # "properties": {
        # /\* The resource provider can choose the values here, but it should only be
        #   returned on a successful operation (status being "Succeeded"). \*/
        #},
        # So try to parse it
        try:
            self.resource = self.get_outputs(response)
        except Exception:
            self.resource = None

    def set_async_url_if_present(self, response):
        async_url = _get_header_url(response, 'azure-asyncoperation')
        if async_url:
            self.async_url = async_url
        
        location_url = _get_header_url(response, 'location')
        if location_url:
            self.location_url = location_url

def handle_exceptions(operation, response):
    try:
        raise
    except BadStatus:
        operation.status = 'Failed'
        raise CloudError(response)
    except BadResponse as err:
        operation.status = 'Failed'
        raise CloudError(response, str(err))
    except OperationFailed:
        raise CloudError(response)
        

if ASYNC_PROTOTYPE:
    from .azure_async_operation import AzureOperationPoller
else:
    from .azure_legacy_poller import AzureOperationPoller
