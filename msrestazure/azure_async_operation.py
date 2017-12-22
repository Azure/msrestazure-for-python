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
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
import asyncio

from .azure_operation import (
    LongRunningOperation,
    BadStatus,
    BadResponse,
    OperationFailed,
    finished,
    failed,
    handle_exceptions
)


class AzureOperationPoller(asyncio.Future):
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

    def __init__(self, send_cmd, output_cmd, update_cmd, timeout=30, *, loop=None):
        super(AzureOperationPoller, self).__init__(loop=loop)
        self._send_cmd = send_cmd
        self._output_cmd = output_cmd
        self._update_cmd = update_cmd
        self._timeout = timeout
        self._operation = None

        asyncio.ensure_future(self._get_coroutine(), loop=loop)

    async def _get_coroutine(self):
        try:
            self._response = await self._send_cmd()
            self._operation = LongRunningOperation(self._response, self._output_cmd)
            self._operation.set_initial_status(self._response)

            if not finished(self.status()):
                await self._poll(self._update_cmd)
        except Exception:
            try:
                handle_exceptions(self._operation, self._response)
            except Exception as err:
                self.set_exception(err)
        else:
            self.set_result(self._operation.resource)

    async def _delay(self):
        """Check for a 'retry-after' header to set timeout,
        otherwise use configured timeout.
        """
        if self._response is None:
            await asyncio.sleep(0)
        if self._response.headers.get('retry-after'):
            await asyncio.sleep(int(self._response.headers['retry-after']))
        else:
            await asyncio.sleep(self._timeout)

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

    async def _poll(self, update_cmd):
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
            await self._delay()
            headers = self._polling_cookie()

            if self._operation.async_url:
                self._response = await update_cmd(
                    self._operation.async_url, headers)
                self._operation.set_async_url_if_present(self._response)
                self._operation.get_status_from_async(
                    self._response)
            elif self._operation.location_url:
                self._response = await update_cmd(
                    self._operation.location_url, headers)
                self._operation.set_async_url_if_present(self._response)
                self._operation.get_status_from_location(
                    self._response)
            elif self._operation.method == "PUT":
                self._response = await update_cmd(initial_url, headers)
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

    def resource(self):
        """Returns the last resource or None if no result is expected.

        :returns: The last resource (subcalss of msrest.serialization.Model) or None
        :rtype: msrest.serialization.Model or None
        """
        return self._operation.status
