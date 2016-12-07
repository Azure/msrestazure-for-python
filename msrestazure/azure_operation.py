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
import threading
import time
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

from msrest.exceptions import DeserializationError
from msrestazure.azure_exceptions import CloudError


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
    :raises: ValueError if URL has not scheme or host.
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
    :returns: URL if valid.
    :raises: ValueError if URL has not scheme or host.
    """
    url = response.headers.get(header_name)
    _validate(url)
    return url

class BadStatus(Exception):
    pass


class BadResponse(Exception):
    pass


class OperationFailed(Exception):
    pass


class OperationFinished(Exception):
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

    def _raise_if_bad_http_status_and_method(self, response):
        """Check response status code is valid for a Put or Patch
        request. Must be 200, 201, 202, or 204.

        :raises: BadStatus if invalid status.
        """
        code = response.status_code
        if code in {200, 202} or \
           (code == 201 and self.method == 'PUT') or \
           (code == 204 and self.method in ['DELETE', 'POST']):
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
        try:
            return body.get("properties", {}).get("provisioningState")
        except AttributeError:
            return None

    def _process_http_status_code(self, response):
        """Process response based on specific status code.

        :param requests.Response response: latest REST call response.
        """
        process = getattr(self, '_status_' + str(response.status_code))
        process(response)

    def _status_200(self, response):
        """Process response with status code 200.

        :param requests.Response response: latest REST call response.
        """
        status = self._get_provisioning_state(response)
        self.status = status or 'Succeeded'

    def _status_201(self, response):
        """Process response with status code 201.

        :param requests.Response response: latest REST call response.
        :raises: BadResponse if response deserializes to CloudError.
        """
        status = self._get_provisioning_state(response)
        self.status = status or 'InProgress'

    def _status_202(self, response):
        """Process response with status code 202.
        Just sets status to 'InProgress'.

        :param requests.Response response: latest REST call response.
        """
        self.status = 'InProgress'

    def _status_204(self, response):
        """Process response with status code 204.
        Interpretted as successful with no payload.

        :param requests.Response response: latest REST call response.
        """
        self.status = 'Succeeded'
        self.resource = None

    def is_done(self, response):
        """Check whether the operation can be considered complete.
        This is based on whether the data in the resource matches the current
        status. If there is not resource, we assume it's complete.

        :param requests.Response response: latest REST call response.
        :rtype: bool
        """
        if (self.async_url or not self.resource) and \
                self.method in {'PUT', 'PATCH'}:
            return False
        resource_state = self._get_provisioning_state(response)
        try:
            return self.status.lower() == resource_state.lower()
        except AttributeError:
            return True

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
            if self.async_url or self.location_url:
                self.status = 'InProgress'
            else:
                self._process_http_status_code(response)
        else:
            self.status = 'Failed'

    def get_status_from_location(self, response):
        """Process the latest status update retrieved from a 'location'
        header.

        :param requests.Response response: latest REST call response.
        :raises: BadResponse if response has no body and not status 202.
        """
        code = response.status_code
        if code == 202:
            self.status = "InProgress"
        elif code == 200 or \
             (code == 201 and self.method == "PUT") or \
             (code == 204 and self.method in {"DELETE", "POST"}):

            status = self._get_provisioning_state(response)
            self.status = status or 'Succeeded'
            if self._is_empty(response):
                self.resource = None
            else:
                self.resource = self.get_outputs(response)

        else:
            raise BadStatus(
                "Invalid return status for {!r} operation".format(self.method))

    def get_status_from_resource(self, response):
        """Process the latest status update retrieved from the same URL as
        the previous request.

        :param requests.Response response: latest REST call response.
        :raises: BadResponse if status not 200 or 204.
        """
        if self._is_empty(response):
            raise BadResponse('The response from long running operation '
                              'does not contain a body.')

        status = self._get_provisioning_state(response)
        self.status = status or 'Succeeded'
        self.resource = self.get_outputs(response)

    def get_status_from_async(self, response):
        """Process the latest status update retrieved from a
        'azure-asyncoperation' header.

        :param requests.Response response: latest REST call response.
        :raises: BadResponse if response has no body, or body does not
         contain status.
        """
        if self._is_empty(response):
            raise BadResponse('The response from long running operation '
                              'does not contain a body.')

        self.status = self._get_async_status(response)
        if not self.status:
            raise BadResponse("No status found in body")

        try:
            self.resource = self.get_outputs(response)
        except Exception:
            self.resource = None

    def set_async_url_if_present(self, response):
        # If already got it, don't replace
        if self.async_url or self.location_url:
            return
        try:
            self.async_url = _get_header_url(response, 'azure-asyncoperation')

            # Return if we have a url, in case location header raises error.
            if self.async_url:
                return
        except ValueError:
            pass  # We can ignore as location header may still be valid.
        self.location_url = _get_header_url(response, 'location')
        if not self.location_url and not self.async_url:
            code = response.status_code
            if code == 202 and self.method == 'POST':
                raise BadResponse(
                    'Location header is missing from long running operation.')


class AzureOperationPoller(object):
    """Initiates long running operation and polls status in separate
    thread.

    :param callable send_cmd: The API request to initiate the operation.
    :param callable update_cmd: The API reuqest to check the status of
        the operation.
    :param callable output_cmd: The function to deserialize the resource
        of the operation.
    :param int timeout: Time in seconds to wait between status calls,
        default is 30.
    :param callable func: Callback function that takes at least one
        argument, a completed LongRunningOperation (optional).
    """

    def __init__(self, send_cmd, output_cmd, update_cmd, timeout=30):
        self._timeout = timeout
        self._response = None
        self._operation = None
        self._exception = None
        self._callbacks = []
        self._done = threading.Event()
        self._thread = threading.Thread(
            target=self._start, args=(send_cmd, update_cmd, output_cmd))
        self._thread.daemon = True
        self._thread.start()

    def _start(self, send_cmd, update_cmd, output_cmd):
        """Start the long running operation.
        On completetion, runs any callbacks.

        :param callable send_cmd: The API request to initiate the operation.
        :param callable update_cmd: The API reuqest to check the status of
         the operation.
        :param callable output_cmd: The function to deserialize the resource
         of the operation.
        """
        try:
            self._response = send_cmd()
            self._operation = LongRunningOperation(self._response, output_cmd)
            self._operation.set_initial_status(self._response)
            self._poll(update_cmd)

        except BadStatus:
            self._operation.status = 'Failed'
            self._exception = CloudError(self._response)

        except BadResponse as err:
            self._operation.status = 'Failed'
            self._exception = CloudError(self._response, str(err))

        except OperationFailed:
            self._exception = CloudError(self._response)

        except OperationFinished:
            pass

        except Exception as err:
            self._exception = err

        finally:
            self._done.set()

        callbacks, self._callbacks = self._callbacks, []
        while callbacks:
            for call in callbacks:
                call(self._operation)
            callbacks, self._callbacks = self._callbacks, []

    def _delay(self):
        """Check for a 'retry-after' header to set timeout,
        otherwise use configured timeout.
        """
        if self._response is None:
            return
        if self._response.headers.get('retry-after'):
            time.sleep(int(self._response.headers['retry-after']))
        else:
            time.sleep(self._timeout)

    def _polling_cookie(self):
        """Collect retry cookie - we only want to do this for the test server
        at this point, unless we implement a proper cookie policy.

        :returns: Dictionary containing a cookie header if required,
         otherwise an empty dictionary.
        """
        parsed_url = urlparse(self._response.request.url)
        host = parsed_url.hostname.strip('.')
        if host == 'localhost':
            return {'cookie': self._response.headers.get('set-cookie', '')}
        return {}

    def _poll(self, update_cmd):
        """Poll status of operation so long as operation is incomplete and
        we have an endpoint to query.

        :param callable update_cmd: The function to call to retrieve the
         latest status of the long running operation.
        :raises: OperationFinished if operation status 'Succeeded'.
        :raises: OperationFailed if operation status 'Failed' or 'Cancelled'.
        :raises: BadStatus if response status invalid.
        :raises: BadResponse if response invalid.
        """
        initial_url = self._response.request.url

        while not finished(self._operation.status):
            self._delay()
            url = self._response.request.url
            headers = self._polling_cookie()

            if self._operation.async_url:
                self._response = update_cmd(
                    self._operation.async_url, headers)
                self._operation.get_status_from_async(
                    self._response)
            elif self._operation.location_url:
                self._response = update_cmd(
                    self._operation.location_url, headers)
                self._operation.get_status_from_location(
                    self._response)
            else:
                self._response = update_cmd(url, headers)
                self._operation.get_status_from_resource(
                    self._response)

        if failed(self._operation.status):
            raise OperationFailed("Operation failed or cancelled")
        elif not self._operation.is_done(self._response):
            self._response = update_cmd(initial_url)
            self._operation.get_status_from_resource(
                self._response)

    def result(self, timeout=None):
        """Return the result of the long running operation, or
        the result available after the specified timeout.

        :returns: The deserialized resource of the long running operation,
         if one is available.
        :raises CloudError: Server problem with the query.
        """
        self.wait(timeout)
        return self._operation.resource

    def wait(self, timeout=None):
        """Wait on the long running operation for a specified length
        of time.

        :param int timeout: Perion of time to wait for the long running
         operation to complete.
        :raises CloudError: Server problem with the query.
        """
        self._thread.join(timeout=timeout)
        try:
            raise self._exception
        except TypeError:
            pass

    def done(self):
        """Check status of the long running operation.

        :returns: 'True' if the process has completed, else 'False'.
        """
        return not self._thread.isAlive()

    def add_done_callback(self, func):
        """Add callback function to be run once the long running operation
        has completed - regardless of the status of the operation.

        :param callable func: Callback function that takes at least one
         argument, a completed LongRunningOperation.
        :raises: ValueError if the long running operation has already
         completed.
        """
        if self._done.is_set():
            raise ValueError("Process is complete.")
        self._callbacks.append(func)

    def remove_done_callback(self, func):
        """Remove a callback from the long running operation.

        :param callable func: The function to be removed from the callbacks.
        :raises: ValueError if the long running operation has already
         completed.
        """
        if self._done.is_set():
            raise ValueError("Process is complete.")
        self._callbacks = [c for c in self._callbacks if c != func]
