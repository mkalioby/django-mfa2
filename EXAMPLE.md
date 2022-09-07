# Use of Example project

1. create virtual env
`virtualenv venv`
1. activate env `source venv/bin/activate`
1. install requirements `pip install -r requirements.txt`
1. cd to example project `cd example`
1. migrate `python manage.py migrate`
1. create super user `python manage.py createsuperuser`
1. start the serveur `python manage.py runserver`

# Notes for SSL

To test FIDO2 you need to use HTTPS, after the above steps are done:

1. stop the server
1. install requirements `pip install -r example-ssl-requirements.txt`
1. start the ssl server `python manage.py runsslserver`
