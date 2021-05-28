# Change of login function

## Break your login function

Usually your login function will check for username and password, log the user in if the username and password are correct and create the user session, to support mfa, this has to change
 
 * authenticate the user
 * if username and password are correct , check if the user has mfa or not
     * if user has mfa then redirect to mfa page
      * if user doesn't have mfa then call your function to create the user session

```python
def login(request): # this function handles the login form POST
    user = auth.authenticate(username=username, password=password)  
    if user is not None: # if the user object exist
         from mfa.helpers import has_mfa
         res =  has_mfa(username = username,request=request) # has_mfa returns false or HttpResponseRedirect
         if res:
             return res
         return log_user_in(request,username=user.username) 
            #log_user_in is a function that handles creatung user session, it should be in the setting file as MFA_CALLBACK
```

