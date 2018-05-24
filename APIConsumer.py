from flask import Flask, redirect, render_template, url_for, request#, abort, flash, session

#import werkzeug.exceptions as ex

from os import urandom, getpid, environ#, path
from binascii import hexlify
import inspect
import logging

import requests as req
from urllib import parse

#from hashlib import sha512

import json

#from google.protobuf import timestamp_pb2
#from gcloud import storage
#
#ID_BUCKET = 'ids'
#
#
#def lookup_bucket(cli, prefix):
#    for bucket in cli.list_buckets():
#        if bucket.name.startswith(prefix):
#            return bucket.name
#    logging.error("Id Bucket not found")


def save_pid():
    """Save pid into a file: filename.pid."""
    pidfilename = inspect.getfile(inspect.currentframe()) + ".pid"
    f = open(pidfilename, 'w')
    f.write(str(getpid()))
    f.close()

save_pid()

logfilename = inspect.getfile(inspect.currentframe()) + ".log"
logging.basicConfig(filename=logfilename, level=logging.INFO, format='%(asctime)s %(message)s')
logging.info("Started")

#filepath = path.join(path.dirname(path.realpath(__file__)), 'tweetfeedplus_ids.py')
#if not path.exists(filepath):
#    client = storage.Client()
#    cblob = client.get_bucket(lookup_bucket(client, ID_BUCKET)).get_blob('tweetfeedplus_ids.py')
#    fp = open(filepath, 'wb')
#    cblob.download_to_file(fp)
#    fp.close()
#
#from tweetfeedplus_ids import id_dict as ids

def generate_url(host, protocol='http', port=80, dir=''):

    if isinstance(dir, list):
        dir = '/'.join(dir)

    return "%s://%s:%d/%s" % (protocol, host, port, dir)

#class NotAllowed(ex.HTTPException):
#    code = 403
#    description = 'This is not the page you are looking for.'
#
#
#class NotValidToken(ex.HTTPException):
#    code = 401
#    description = 'Invalid Twitter Token'
#
#abort.mapping[401] = NotValidToken
#abort.mapping[403] = NotAllowed
#
#
#def no_impostors_wanted(s):
#    if (not s['logged_in']) if 'logged_in' in s.keys() else True:
#        abort(403)


IP = req.get(generate_url('jsonip.com')).json()['ip']

DEFAULT_PORT = 80
PORT = int(environ.get('PORT', DEFAULT_PORT))

API_HOST = parse(request.base_url).hostname.split('.')[0] + '-api.herokuapp.com'
API_PROTOCOL = 'https'
API_PORT = 88 if PORT == DEFAULT_PORT else 80
API_ENDPOINT = generate_url(API_HOST, protocol=API_PROTOCOL, dir=['api', 'infer'], port=API_PORT)
#API_HOST = IP
#API_HOST = '130.211.59.105'

app = Flask(__name__, static_url_path="", static_folder='static')
flask_options = dict(port=PORT, host='0.0.0.0')
def run():
    app.secret_key = hexlify(urandom(24))
    app.run(**flask_options)


@app.route('/')
def root():
    return redirect(url_for('index'))


@app.route('/index')
def index():
    return render_template('index.html')


#@app.route('/logout')
#def logout():
#    del session['username']
#    session['logged_in'] = False
#    return redirect(url_for('index'))


@app.route('/api/infer', methods=['POST'])
def api_infer():
    #no_impostors_wanted(session)
    image = request.form['image']
    model = request.form['model']
    result = req.post(API_ENDPOINT, data=json.dumps(dict(image=image, model=model)))
    return json.dumps(result.json())


#@app.route('/login', methods=['GET', 'POST'])
#def login():
#    if request.method == 'POST':
#        uname = request.form['username']
#        if uname in ids.keys():
#            pwd = request.form['password']
#            pwd = pwd.encode('latin1')
#            digest = sha512(pwd).hexdigest()
#            if ids[uname] == digest:
#                session['username'] = request.form['username']
#                session['logged_in'] = True
#                return redirect(url_for('index'))
#            flash('Password did not match that for the login provided', 'bad_login')
#            return render_template('login.html')
#        flash('Unknown username', 'bad_login')
#    return render_template('login.html')


@app.route('/test_api', methods=['GET'])
def test_api():
    #no_impostors_wanted(session)
    return render_template('test_api.html', API_ENDPOINT=API_ENDPOINT)

@app.after_request
def apply_caching(response):
    #response.headers["X-Frame-Options"] = "ALLOW-FROM http://eh-aibjuwgkwtg.preview.forestry.io/"
    response.headers["Content-Security-Policy"] = "frame-ancestors http://www.human-forecast.com http://www.human-forecast.com/* http://www.human-forecast.es http://www.human-forecast.es/* https://exp-ai.com https://exp-ai.com/* 'self'"
    return response

if __name__ == '__main__':
    run()
