from flask import Flask, abort, flash, redirect, render_template, session, url_for, request

import werkzeug.exceptions as ex

from os import urandom, path
from binascii import hexlify

import requests as req

from hashlib import sha512

from google.protobuf import timestamp_pb2
from gcloud import storage

ID_BUCKET = 'ids-hf'

# Descargamos el dataset de cancer del bucket de datasets
client = storage.Client()
cblob = client.get_bucket(ID_BUCKET).get_blob('tweetfeedplus_ids.py')
fp = open(path.join('app', 'tweetfeedplus_ids.py'), 'wb')
cblob.download_to_file(fp)
fp.close()

from tweetfeedplus_ids import id_dict as ids

def generate_url(host, protocol='http', port=80, dir=''):

    if isinstance(dir, list):
        dir = '/'.join(dir)

    return "%s://%s:%d/%s" % (protocol, host, port, dir)

class NotAllowed(ex.HTTPException):
    code = 403
    description = 'This is not the page you are looking for.'


class NotValidToken(ex.HTTPException):
    code = 401
    description = 'Invalid Twitter Token'

abort.mapping[401] = NotValidToken
abort.mapping[403] = NotAllowed


def no_impostors_wanted():
    if (not session['logged_in']) if 'logged_in' in session.keys() else False:
        abort(403)


#MYIP = '127.0.0.1'
MYIP = req.get(generate_url('jsonip.com')).json()['ip']

app = Flask(__name__, static_url_path="", static_folder='static')
flask_options = dict(port=80, host='0.0.0.0')
def run():
    app.secret_key = hexlify(urandom(24))
    app.run(**flask_options)


@app.route('/')
def root():
    return redirect(url_for('index'))


@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/logout')
def logout():
    del session['username']
    session['logged_in'] = False
    return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form['username']
        if uname in ids.keys():
            if ids[uname] == sha512(bytes(request.form['password'], encoding='latin1')).hexdigest():
                session['username'] = request.form['username']
                session['logged_in'] = True
                return redirect(url_for('index'))
            flash('Password did not match that for the login provided', 'bad_login')
            return render_template('login.html')
        flash('Unknown username', 'bad_login')
    return render_template('login.html')


@app.route('/test_api', methods=['GET'])
def test_api():
    no_impostors_wanted()
    return render_template('test_api.html', IP=MYIP)

if __name__ == '__main__':
    run()