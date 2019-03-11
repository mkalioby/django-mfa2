# django-mfa2
A Django app that handles MFA, it supports TOTP, U2F, FIDO2 U2F (Web Authn), Email Tokens , and Trusted Devices

[![PyPI version](https://badge.fury.io/py/django-mfa2.svg)](https://badge.fury.io/py/django-mfa2)

Web Authencation API (WebAuthn) is state-of-the art techology that is expected to replace passwords.

![Andriod Fingerprint](https://cdn-images-1.medium.com/max/800/1*1FWkRE8D7NTA2Kn1DrPjPA.png)

For FIDO2, both security keys and android-safetynet are supported.

In English :), It allows you to verify the user by security keys on PC, Laptops and Fingerprint/PIN on Andriod Phones.

Trusted device is a mode for the user to add a device that doesn't support security keys like iOS and andriod without fingerprints or NFC.

**Note**: `U2F and FIDO2 can only be served under secure context (https)`

Package tested with Django 1.8, Django 2.1 on Python 2.7 and Python 3.5+ but it was not checked with any version in between but open for issues.

Depends on

* pyotp
* python-u2flib-server
* ua-parser
* user-agents
* python-jose
* fido2==0.5

# Example

For Example, See https://github.com/mkalioby/AutoDeploy/commit/5f1d94b1804e0aa33c79e9e8530ce849d9eb78cc in AutDeploy Project

# Table of Contents
* [Installation](installation.md)
* [Change Login Code](change_login.md)

