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
import threading
import time
import uuid
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

from msrestazure.azure_exceptions import CloudError
from .azure_operation import (
    LongRunningOperation,
    BadStatus,
    BadResponse,
    OperationFailed,
    finished,
    failed,
    handle_exceptions
)

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
    """

    def __init__(self, send_cmd, output_cmd, update_cmd, timeout=30):
        self._timeout = timeout
        self._callbacks = []

        try:
            self._response = send_cmd()
            self._operation = LongRunningOperation(self._response, output_cmd)
            self._operation.set_initial_status(self._response)
        except Exception:
            handle_exceptions(self._operation, self._response)

        self._thread = None
        self._done = None
        self._exception = None
        if not finished(self.status()):
            self._done = threading.Event()
            self._thread = threading.Thread(
                target=self._start,
                name="AzureOperationPoller({})".format(uuid.uuid4()),
                args=(update_cmd,))
            self._thread.daemon = True
            self._thread.start()

    def _start(self, update_cmd):
        """Start the long running operation.
        On completion, runs any callbacks.

        :param callable update_cmd: The API reuqest to check the status of
         the operation.
        """
        try:
            self._poll(update_cmd)
        except Exception:
            try:
                handle_exceptions(self._operation, self._response)
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
        :raises: OperationFailed if operation status 'Failed' or 'Cancelled'.
        :raises: BadStatus if response status invalid.
        :raises: BadResponse if response invalid.
        """
        initial_url = self._response.request.url

        while not finished(self.status()):
            self._delay()
            headers = self._polling_cookie()

            if self._operation.async_url:
                self._response = update_cmd(
                    self._operation.async_url, headers)
                self._operation.set_async_url_if_present(self._response)
                self._operation.get_status_from_async(
                    self._response)
            elif self._operation.location_url:
                self._response = update_cmd(
                    self._operation.location_url, headers)
                self._operation.set_async_url_if_present(self._response)
                self._operation.get_status_from_location(
                    self._response)
            elif self._operation.method == "PUT":
                self._response = update_cmd(initial_url, headers)
                self._operation.set_async_url_if_present(self._response)
                self._operation.get_status_from_resource(
                    self._response)
            else:
                raise BadResponse(
                    'Location header is missing from long running operation.')

        if failed(self._operation.status):
            raise OperationFailed("Operation failed or cancelled")
        elif self._operation.should_do_final_get():
            self._response = update_cmd(initial_url)
            self._operation.get_status_from_resource(
                self._response)

    def status(self):
        """Returns the current status string.

        :returns: The current status string
        :rtype: str
        """
        return self._operation.status

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
        if self._thread is None:
            return
        self._thread.join(timeout=timeout)
        try:
            raise self._exception
        except TypeError:
            pass

    def done(self):
        """Check status of the long running operation.

        :returns: 'True' if the process has completed, else 'False'.
        """
        return self._thread is None or not self._thread.isAlive()

    def add_done_callback(self, func):
        """Add callback function to be run once the long running operation
        has completed - regardless of the status of the operation.

        :param callable func: Callback function that takes at least one
         argument, a completed LongRunningOperation.
        :raises: ValueError if the long running operation has already
         completed.
        """
        if self._done is None or self._done.is_set():
            raise ValueError("Process is complete.")
        self._callbacks.append(func)

    def remove_done_callback(self, func):
        """Remove a callback from the long running operation.

        :param callable func: The function to be removed from the callbacks.
        :raises: ValueError if the long running operation has already
         completed.
        """
        if self._done is None or self._done.is_set():
            raise ValueError("Process is complete.")
        self._callbacks = [c for c in self._callbacks if c != func]
