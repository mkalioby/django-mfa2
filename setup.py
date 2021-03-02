#!/usr/bin/env python

from setuptools import find_packages, setup

setup(
    name='django-mfa2',
    version='2.1.2',
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
        'django >= 2.0',
        'jsonfield',
        'simplejson',
        'pyotp',
        'python-u2flib-server',
        'ua-parser',
        'user-agents',
        'python-jose',
        'fido2 == 0.9.1',
        'jsonLookup'
      ],
    python_requires=">=3.5",
    include_package_data=True,
    zip_safe=False, # because we're including static files
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Framework :: Django",
        "Framework :: Django :: 1.11",
        "Framework :: Django :: 2.0",
        "Framework :: Django :: 2.1",
        "Framework :: Django :: 2.2",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Software Development :: Libraries :: Python Modules",
]
)
