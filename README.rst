AutoRest: Python Client Runtime - Azure Module
===============================================

.. image:: https://travis-ci.org/Azure/msrestazure-for-python.svg?branch=master
 :target: https://travis-ci.org/Azure/msrestazure-for-python

.. image:: https://codecov.io/gh/azure/msrestazure-for-python/branch/master/graph/badge.svg
 :target: https://codecov.io/gh/azure/msrestazure-for-python

Installation
------------

To install:

.. code-block:: bash

    $ pip install msrestazure


Release History
---------------

2017-06-19 Version 0.4.9
++++++++++++++++++++++++

**Features**

- Add proxies parameters to ServicePrincipal and UserPassword credentials class #29
- Add automatic Azure provider registration if needed (requires msrest 0.4.10) #28

Thank you to likel for his contribution

2017-05-31 Version 0.4.8
++++++++++++++++++++++++

**Bugfixes**

- Fix LRO if first call never returns 200, but ends on 201 (#26)
- FiX LRO AttributeError if timeout is short (#21)

**Features**

- Expose a "status()" method in AzureOperationPoller (#18)

2017-01-23 Version 0.4.7
++++++++++++++++++++++++

**Bugfixes**

- Adding `accept_language` and `generate_client_request_id ` default values

2016-12-12 Version 0.4.6
++++++++++++++++++++++++

**Bugfixes**

Refactor Long Running Operation algorithm.

- There is no breaking changes, however you might need to record again your offline HTTP records
  if you use unittests with VCRpy.
- Fix a couple of latent bugs

2016-11-30 Version 0.4.5
++++++++++++++++++++++++

**New features**

- Add AdalAuthentification class to wrap ADAL library (https://github.com/Azure/msrestazure-for-python/pull/8)

2016-10-17 Version 0.4.4
++++++++++++++++++++++++

**Bugfixes**

- More informative and well-formed CloudError exceptions (https://github.com/Azure/autorest/issues/1460)
- Raise CustomException is defined in Swagger (https://github.com/Azure/autorest/issues/1404)

2016-09-14 Version 0.4.3
++++++++++++++++++++++++

**Bugfixes**

- Make AzureOperationPoller thread as daemon (do not block anymore a Ctrl+C) (https://github.com/Azure/autorest/pull/1379)

2016-09-01 Version 0.4.2
++++++++++++++++++++++++

**Bugfixes**

- Better exception message (https://github.com/Azure/autorest/pull/1300)

This version needs msrest >= 0.4.3

2016-06-08 Version 0.4.1
++++++++++++++++++++++++

**Bugfixes**

- Fix for LRO PUT operation https://github.com/Azure/autorest/issues/1133

2016-05-25 Version 0.4.0
++++++++++++++++++++++++

Update msrest dependency to 0.4.0

**Bugfixes**

- Fix for several AAD issues https://github.com/Azure/autorest/issues/1055
- Fix for LRO PATCH bug and refactor https://github.com/Azure/autorest/issues/993

**Behaviour changes**

- Needs Autorest > 0.17.0 Nightly 20160525


2016-04-26 Version 0.3.0
++++++++++++++++++++++++

Update msrest dependency to 0.3.0

**Bugfixes**

- Read only values are no longer in __init__ or sent to the server (https://github.com/Azure/autorest/pull/959)
- Useless kwarg removed

**Behaviour changes**

- Needs Autorest > 0.16.0 Nightly 20160426


2016-03-31 Version 0.2.1
++++++++++++++++++++++++

**Bugfixes**

- Fix AzurePollerOperation if Swagger defines provisioning status as enum type (https://github.com/Azure/autorest/pull/892)


2016-03-25 Version 0.2.0
++++++++++++++++++++++++

Update msrest dependency to 0.2.0

**Behaviour change**

- async methods called with raw=True don't return anymore AzureOperationPoller but ClientRawResponse
- Needs Autorest > 0.16.0 Nightly 20160324


2016-03-21 Version 0.1.2
++++++++++++++++++++++++

Update msrest dependency to 0.1.3

**Bugfixes**

- AzureOperationPoller.wait() failed to raise exception if query error (https://github.com/Azure/autorest/pull/856)


2016-03-04 Version 0.1.1
++++++++++++++++++++++++

**Bugfixes**

- Source package corrupted in Pypi (https://github.com/Azure/autorest/issues/799)

2016-03-04 Version 0.1.0
++++++++++++++++++++++++

**Behaviour change**

- Replaced _required attribute in CloudErrorData class with _validation dict.

2016-02-29 Version 0.0.2
++++++++++++++++++++++++

**Bugfixes**

- Fixed AAD bug to include connection verification in UserPassCredentials. (https://github.com/Azure/autorest/pull/725)
- Source package corrupted in Pypi (https://github.com/Azure/autorest/issues/718)

2016-02-19 Version 0.0.1
++++++++++++++++++++++++

- Initial release.
