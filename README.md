# MyJohnDeereAPI-OAuth-Python-Client

## System Requirements and installation
1. Download and install Python 3.4
    For installation follow [this](https://github.com/BurntSushi/nfldb/wiki/Python-&-pip-Windows-installation) instruction.

2. Download Request OAuthlib from https://github.com/requests/requests-oauthlib or run pip install requests requests_oauthlib command

#### Execute
1. Run apiclient.py file. You will see below options.
   ```
    Selecting credentials...
    Reading credentials store...
    Credentials store doesn't exist, creating...
    Created credentials store at "C:\bench\MyJohnDeereAPI-OAuth-Python-Client\credentials_store"
    Done reading credentials store.
    a : Add a new set of credentials
    q : Quit program
    Your choice?:
   ```   
2. Enter "a" for adding new tokens.
3. Enter the username for Owner option
4. Enter the appId/client key and secret from developer.deere.com when prompted.
5. You will see these below options. Select "a" again to add a access token and token secret.

   ```
    Selecting a token...
    Reading tokens store...
    Tokens store doesn't exist, creating...
    Created tokens store at "Your code path\token_store"
    Done reading tokens store.
    a : add a new token
    q : quit program
    Your choice?: 
   ```
6. Copy the url from the reponse which says "follow this link to authorize" into browser which will ask
   for login. Login with your johndeere credentails.
   ```
    Step 1: use urls from catalog to fetch a request token (using same client security context)
    {
        "oauth_callback_confirmed": "true", 
        "oauth_token": "REQUEST_TOKEN", 
        "oauth_token_secret": "REQUEST_TOKEN_SECRET"
    }
    Enter to continue...
    Step 2: follow this link to authorize (this requires action by the user)
    https://my.deere.com/consentToUseOfData?oauth_token=REQUEST_TOKEN
    Paste full redirect url: 
   ```
7. Copy the generated url from the browser, which looks something like this:
   ```
   http://127.0.0.1/callback?oauth_token=YOUR_TOKEN&oauth_verifier=YOUR_VERIFIER
   ```
   to the console to generate access token. Which looks like this
   ```
   Step 3: fetch access token
      {
          "oauth_token": "REQUEST_TOKEN", 
          "oauth_verifier": "YOUR_VERIFIER"
      }
      Access token and secret:
      {
          "oauth_token": "ACCESS_TOKEN", 
          "oauth_token_secret": "ACCESS_TOKEN_SECRET"
      }
      Enter to continue...Updating token store...
      Done updating token store.
    ```
8. Select an option from below to either upload/download/delete a file from your operations center.
   Or enter relative url something like /organizations.   
   ``` 
   u : upload a file
    d : download a file
    r : remove a file
      : enter any resource URI starting with '/'
      : follow any relationship using the rel name
    q : quit program
    Your choice?: 
   ```
