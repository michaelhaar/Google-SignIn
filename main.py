from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello, World!'

if __name__ == '__main__':
    # enable debug support; the server will reload itself on code changes
    app.debug = True
    # By default the Flask server is only accessible from the host machine and
    # not from any other computer.
    # Since we are using a Vagrant environment (=virtual machine), we must make
    # our server publicly available. This is done with the following line:
    app.run(host = '0.0.0.0', port = 5000)
