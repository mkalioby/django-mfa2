#!/usr/bin/env python

from setuptools import find_packages, setup

setup(
    name='django-mfa2',
    version='0.9.2',
    description='Allows user to add 2FA to their accounts',
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",

    author='Mohamed El-Kalioby',
    author_email = 'mkalioby@mkalioby.com',
    url = 'https://github.com/mkalioby/django-mfa2/',

    download_url='https://github.com/mkalioby/django-mfa2/',
    license='MIT',
    packages=find_packages(),
    install_requires=[
        'Django>=1.7',
        'jsonfield',
        'simplejson',
        'pyotp',
        'python-u2flib-server',
        'ua-parser',
        'user-agents',
        'python-jose',
        'fido2==0.5'
        'jsonLookup'
      ],
    include_package_data=True,
      zip_safe=False, # because we're including static files
)
