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

import json
import re
import logging
import time
import uuid

_LOGGER = logging.getLogger(__name__)

def register_rp_hook(r, *args, **kwargs):
    """This is a requests hook to register RP automatically.

    See requests documentation for details of the signature of this function.
    http://docs.python-requests.org/en/master/user/advanced/#event-hooks
    """
    if r.status_code == 409 and 'msrest' in kwargs:
        rp_name = _check_rp_not_registered_err(r)
        if rp_name:
            session = kwargs['msrest']['session']
            url_prefix = _extract_subscription_url(r.request.url)
            if not _register_rp(session, url_prefix, rp_name):
                return
            req = r.request
            # Change the 'x-ms-client-request-id' otherwise the Azure endpoint
            # just returns the same 409 payload without looking at the actual query
            if 'x-ms-client-request-id' in req.headers:
                req.headers['x-ms-client-request-id'] = str(uuid.uuid1())
            return session.send(req)

def _check_rp_not_registered_err(response):
    try:
        response = json.loads(response.content.decode())
        if response['error']['code'] == 'MissingSubscriptionRegistration':
            match = re.match(r".*'(.*)'", response['error']['message'])
            return match.group(1)
    except Exception:  # pylint: disable=broad-except
        pass
    return None

def _extract_subscription_url(url):
    """Extract the first part of the URL, just after subscription:
    https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000000/
    """
    match = re.match(r".*/subscriptions/[a-f0-9-]+/", url, re.IGNORECASE)
    if not match:
        raise ValueError("Unable to extract subscription ID from URL")
    return match.group(0)

def _register_rp(session, url_prefix, rp_name):
    """Synchronously register the RP is paremeter.
    
    Return False if we have a reason to believe this didn't work
    """
    post_url = "{}providers/{}/register?api-version=2016-02-01".format(url_prefix, rp_name)
    get_url = "{}providers/{}?api-version=2016-02-01".format(url_prefix, rp_name)
    _LOGGER.warning("Resource provider '%s' used by this operation is not "
                    "registered. We are registering for you.", rp_name)
    post_response = session.post(post_url)
    if post_response.status_code != 200:
        _LOGGER.warning("Registration failed. Please register manually.")
        return False

    while True:
        time.sleep(10)
        rp_info = session.get(get_url).json()
        if rp_info['registrationState'] == 'Registered':
            _LOGGER.warning("Registration succeeded.")
            return True
