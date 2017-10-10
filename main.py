from flask import Flask, render_template, session
import random, string, json

app = Flask(__name__)

with open('client_secret.json', 'r') as f:
    read_data = f.read()
    CLIENT_ID = json.loads(read_data)['web']['client_id']


@app.route('/')
def main():
    return 'Hello, World!'

@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    session['state'] = state
    # Display the session state for debugging:
    # return "The current session state is %s" % session['state']
    # Render the login template
    return render_template('login.html',
                           clientid=CLIENT_ID,
                           CSRF_state_token=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    pass


if __name__ == '__main__':
    # TODO check why is the following line necessary (-> sth with Sessions)
    app.secret_key = 'super_secret_key'
    # enable debug support; the server will reload itself on code changes
    app.debug = True
    # By default the Flask server is only accessible from the host machine and
    # not from any other computer.
    # Since we are using a Vagrant environment (=virtual machine), we must make
    # our server publicly available. This is done with the following line:
    app.run(host = '0.0.0.0', port = 5000)
