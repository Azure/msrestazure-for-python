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

2017-10-31 Version 0.4.16
+++++++++++++++++++++++++

**Bugfixes**

- Fix AttributeError if input JSON is not a dict (#54)

2017-10-13 Version 0.4.15
+++++++++++++++++++++++++

**Features**

- Add support for WebApp/Functions in MSIAuthentication classes
- Add parse_resource_id(), resource_id(), validate_resource_id() to parse ARM ids
- Retry strategy now n reach 24 seconds (instead of 12 seconds)

2017-09-11 Version 0.4.14
+++++++++++++++++++++++++

**Features**

- Add Managed Service Integrated (MSI) authentication

**Bug fix**

- Fix AdalError handling in some scenarios (#44)

Thank you to Hexadite-Omer for his contribution

2017-08-24 Version 0.4.13
+++++++++++++++++++++++++

**Features**

- "keyring" is now completely optional

2017-08-23 Version 0.4.12
+++++++++++++++++++++++++

**Features**

- add "timeout" to ServicePrincipalCredentials and UserPasswordCredentials
- Threads created by AzureOperationPoller have now a name prefixed by "AzureOperationPoller" to help identify them

**Bugfixes**

- Do not fail if keyring is badly installed
- Update Azure Gov login endpoint
- Update metadata ARM endpoint parser

**Breaking changes**

- Remove InteractiveCredentials. This class was deprecated and unusable. Use ADAL device code instead.

2017-06-29 Version 0.4.11
+++++++++++++++++++++++++

**Features**

- Add cloud definitions for public Azure, German Azure, China Azure and Azure Gov
- Add get_cloud_from_metadata_endpoint to automatically create a Cloud object from an ARM endpoint
- Add `cloud_environment` to all Credentials objects (except AdalAuthentication)

**Note**

- This deprecates "china=True", to be replaced by "cloud_environment=AZURE_CHINA_CLOUD"

Example:

.. code:: python

  from msrestazure.azure_cloud import AZURE_CHINA_CLOUD
  from msrestazure.azure_active_directory import UserPassCredentials

  credentials = UserPassCredentials(
      login,
      password,
      cloud_environment=AZURE_CHINA_CLOUD
  )

`base_url` of SDK client can be pointed to "cloud_environment.endpoints.resource_manager" for basic scenario:

Example:

.. code:: python

  from msrestazure.azure_cloud import AZURE_CHINA_CLOUD
  from msrestazure.azure_active_directory import UserPassCredentials
  from azure.mgmt.resource import ResourceManagementClient

  credentials = UserPassCredentials(
      login,
      password,
      cloud_environment=AZURE_CHINA_CLOUD
  )
  client = ResourceManagementClient(
      credentials,
      subscription_id,
      base_url=AZURE_CHINA_CLOUD.endpoints.resource_manager
  )

Azure Stack connection can be done:

.. code:: python

  from msrestazure.azure_cloud import get_cloud_from_metadata_endpoint
  from msrestazure.azure_active_directory import UserPassCredentials
  from azure.mgmt.resource import ResourceManagementClient

  mystack_cloud = get_cloud_from_metadata_endpoint("https://myazurestack-arm-endpoint.com")
  credentials = UserPassCredentials(
      login,
      password,
      cloud_environment=mystack_cloud
  )
  client = ResourceManagementClient(
      credentials,
      subscription_id,
      base_url=mystack_cloud.endpoints.resource_manager
  )


2017-06-27 Version 0.4.10
+++++++++++++++++++++++++

**Bugfixes**

- Accept PATCH/201 as LRO valid state
- Close token session on exit (ServicePrincipal and UserPassword credentials)

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

- Adding `accept_language` and `generate_client_request_id` default values

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
