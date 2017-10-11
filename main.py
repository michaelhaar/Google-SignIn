#!/usr/bin/env python3
# coding=utf8

import flask
import random, string, json, httplib2, requests
from oauth2client import client

app = flask.Flask(__name__)

#TODO maybe create a function out of this
with open('client_secrets.json', 'r') as f:
    read_data = f.read()
    CLIENT_ID = json.loads(read_data)['web']['client_id']


@app.route('/')
def main():
    return 'Hello, World!'


@app.route('/login')
def showLogin():
    # Create a state token to prevent request forgery (-> CRSF) acc. to:
    # https://developers.google.com/identity/protocols/OpenIDConnect
    # Store it in the session for later validation.
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    flask.session['state'] = state
    # Display the session state for debugging:
    # return "The current session state is %s" % flask.session['state']
    # Render the login template
    return flask.render_template('login.html',
                           clientid=CLIENT_ID,
                           CSRF_state_token=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # TODO add some docstrings

    # Store the data from the POST request in variables
    client_state = flask.request.args.get('state')
    auth_code = flask.request.data

    # Ensure that the request is not a forgery (CRSF) and that the user sending
    # this connect request is the expected user. More details can be found
    # under the following link:
    # https://developers.google.com/identity/protocols/OpenIDConnect
    if client_state != flask.session['state']:
        # no further authentication will occur on the server side if there is
        # a mismatch between these state tokens.
        return responseWith('Invalid state token', 401)
    else:
        return tryOAuthFlow(auth_code)


def tryOAuthFlow(auth_code):
    #TODO add docstring and link to official documentation
    #TODO check if one-time-authentication or one-time-authorization
    # Try to use this one-time-authorization code and exchange it for a
    # credentials object.
    print(flask.url_for('gconnect', _external=True))
    try:
        flow = client.flow_from_clientsecrets(
            'client_secrets.json',
            scope = '') #TODO maybe I need to change this
        flow.redirect_uri = 'postmessage'
        credentials = flow.step2_exchange(auth_code)
        return validateAccess(credentials)
    except client.FlowExchangeError:
        return responseWith('Failed to upgrade the authorization code', 401)


def validateAccess(credentials):
    # Check that the access token is valid. TODO where does the url come from?
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    # Submit request, parse response - Python3 compatible
    h = httplib2.Http()
    # Calling the google tokeninfo endpoint
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')  #TODO where does this came from?
    result = json.loads(str_response)

    # If there was an error in the access token info, abort.
    tokeninfo_error_msg = result.get('error')
    if tokeninfo_error_msg is not None:
        return responseWith(tokeninfo_error_msg, 500)

    # Verify that the access token is used for the intended user.
    user_id = credentials.id_token['sub']
    if result['user_id'] != user_id:
        return responseWith("Token's user ID doesn't match given user ID.", 401)

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        return responseWith("Token's client ID does not match app's.", 401)

    return checkIfUserIsLoggedIn(credentials, user_id)

def checkIfUserIsLoggedIn(credentials, user_id):
    stored_credentials = flask.session.get('credentials')
    stored_user_id = flask.session.get('user_id')
    if (stored_credentials is not None and
        stored_user_id == user_id):
        # user has already been logged in.
        return responseWith('Current user is already logged in.', 200)
    else:
        return storeCredentials(credentials, user_id)


def storeCredentials(credentials, user_id):
    flask.session['credentials'] = credentials.to_json()
    flask.session['user_id'] = user_id

    return getUserInfo(credentials)


def getUserInfo(credentials):
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    flask.session['username'] = data['name']
    flask.session['picture'] = data['picture']
    flask.session['email'] = data['email']

    output = ''
    output += '<h1>Welcome, '
    output += flask.session['username']
    output += '!</h1>'
    output += '<img src="'
    output += flask.session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flask.flash("you are now logged in as %s" % flask.session['username'])
    return output


def responseWith(message, response_code):
    response = flask.make_response(json.dumps(message), response_code)
    response.headers['Content-Type'] = 'application/json'
    return response


if __name__ == '__main__':
    # Flask's `session` objects are build on top of cookies and are signed
    # cryptographically. Therefore we need a secret key
    # --> Users can read the content of our cookie, but not modify it.
    # http://flask.pocoo.org/docs/0.12/quickstart/#sessions
    import uuid
    app.secret_key = str(uuid.uuid4())

    # enable debug support; the server will reload itself on code changes
    app.debug = True

    # By default the Flask server is only accessible from the host machine and
    # not from any other computer.
    # Since we are using a Vagrant environment (=virtual machine), we must make
    # our server publicly available. This is done with the following line:
    app.run(host = '0.0.0.0', port = 5000)
