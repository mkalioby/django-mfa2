#!/usr/bin/env python

from setuptools import find_packages, setup

setup(
    name='django-mfa2',
    version='1.8.0',
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
        'django >= 1.7',
        'jsonfield',
        'simplejson',
        'pyotp',
        'python-u2flib-server',
        'ua-parser',
        'user-agents',
        'python-jose',
        'fido2 == 0.7.2',
        'jsonLookup'
      ],
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*",
    include_package_data=True,
      zip_safe=False, # because we're including static files
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Framework :: Django",
        "Framework :: Django :: 1.7",
        "Framework :: Django :: 1.8",
        "Framework :: Django :: 1.9",
        "Framework :: Django :: 1.10",
        "Framework :: Django :: 1.11",
        "Framework :: Django :: 2.0",
        "Framework :: Django :: 2.1",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Topic :: Software Development :: Libraries :: Python Modules",
]
)
