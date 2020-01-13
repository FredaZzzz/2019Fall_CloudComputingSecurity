# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# [START gae_python37_app]
from flask import Flask, send_from_directory, request, render_template, redirect, url_for, make_response
from google.cloud import datastore
import json, bcrypt, random, time, datetime, requests, base64
from datetime import timedelta, timezone


# If `entrypoint` is not defined in app.yaml, App Engine will look for an app
# called `app` in `main.py`.
app = Flask(__name__, template_folder='static')
DS = datastore.Client()
EVENT = "event"
#domain = "lab3-dot-amiable-reducer-251721.appspot.com"
#oidc = 'oidc'

domain = "amiable-reducer-251721.appspot.com"
oidc = 'oidcauth'

#domain = "test-dot-amiable-reducer-251721.appspot.com"
#oidc = 'oidctest'

def put_event(name, date_str, userKey):
    """
    Take variables: {name} {date_str} {userKey}, 
    insert into cloud datastore DS
    allow duplication
    """
    entity = datastore.Entity(key=DS.key(EVENT))
    entity.update({'name': name, 'date': date_str, 'UserID':userKey})
    DS.put(entity)
    return True


def delete_event(name, date, ukey):
    """
    Take variables: {name} {date_str} {userKey}, 
    delete fron cloud datastore DS
    in the case for duplicated entries,
    only one entry will be deleted
    """
    query = DS.query(kind="event")
    query.add_filter('UserID','=',ukey)
    query.add_filter('name','=',name)
    query.add_filter('date','=',date)
    events = list(query.fetch())
    if len(events) < 1:
        return 0
    DS.delete(events[0].key)
    return 1


def gen_token(len):
    """
    Returns a string as token, length is given
    """
    token = ""
    for i in range(len):
        token +=  chr(random.randrange(65,126))
    return token


def get_user_key(token):
    """
    Given the token from browser cookie, 
    find the corresponsing user entry, and 
    return its key. 
    """
    query = DS.query(kind='session')
    query.add_filter('Token', '=', token)
    result = list(query.fetch())
    if len(result) != 1:
        return "Error: multiple users"
    else:
        return(result[0]['UserID'])


def unpack_jwt(id_token):
    _, body, _ = id_token.split('.')
    body += '=' * (-len(body) % 4)
    claims = json.loads(base64.urlsafe_b64decode(body.encode('utf-8')))
    return claims



@app.route('/events')
def returnEvents():
    """
    Upon receipt of a GET '/events' request,
    convert json to string and add to datastore
    """
    ukey = get_user_key(request.cookies.get('login_cookie'))
    query = DS.query(kind='event')
    query.add_filter('UserID','=',ukey)
    results = list(query.fetch())
    num = len(results)
    for i in range(num):
        del results[i]['UserID']
    temp = json.dumps(results)
    temp = '{"events": ' + temp + '}'
    return temp


@app.route('/event', methods=['POST', 'DELETE'])
def manageEvent():
    """
    Upon receipt of a POST '/event' request,
    convert json to string and add to datastore.
    Upon receipt of a DELETE '/event' request,
    search for the event and delete the entry from datastore.
    """
    if request.method == 'POST':
        temp = json.loads(request.json)
        ukey = get_user_key(request.cookies.get('login_cookie'))
        put_event(temp['name'].strip(), temp['date'].strip(), ukey)
        return 'ok'
    else:
        temp = json.loads(request.json)
        ukey = get_user_key(request.cookies.get('login_cookie'))
        a = delete_event(temp['name'], temp['date'], ukey)
        if a==0:
            return request.cookies.get('login_cookie')
        else:
            return 'event(s) deleted'


@app.route('/login', methods=['GET','POST'])
def login():
    """
    Verify login credentials, on failure, stay on login page.
    On success, send back index page with cookie. 
    """
    username = request.form['username'].strip()
    password = request.form['password'].strip()
    query = DS.query(kind='user')
    query.add_filter('Username', '=', username)
    results = list(query.fetch())
    if len(results) == 0:
        return "no such user"
    db_uname=results[0]['Username']
    db_pwd = results[0]['Password']
    userKey = results[0].key;
    if isinstance(password, str):
        password=password.encode()
    if isinstance(db_pwd, str):
        db_pwd = db_pwd.encode()
    if username == db_uname and bcrypt.hashpw(password, db_pwd) == db_pwd:
        #if login credentials match, send cookie, redirect to index.
        token = gen_token(10)
        exp = datetime.datetime.now(timezone.utc)
        exp = exp + timedelta(hours=1)
        entity = datastore.Entity(key=DS.key("session"))
        entity.update({'Token': token, 'Expires': exp, 'Domain': domain, 'UserID':userKey})
        DS.put(entity)
        #set-cookie header
        resp = make_response(render_template("index.html"))
        resp.set_cookie("login_cookie", value=token, max_age=3600, domain=domain, secure=True)
        return resp
    else:
        return render_template("login.html", error="Invalid credentials")
        

@app.route('/logout')
def logout():
    """
    When logout button is clicked, delete all session entries related to that user.
    """
    ukey = get_user_key(request.cookies.get('login_cookie'))
    query = DS.query(kind="session")
    query.add_filter('UserID','=',ukey)
    sessions = list(query.fetch())
    for session in sessions:
        DS.delete(session.key)
    return redirect(url_for('login_page'))


@app.route('/')
def loadHtml():
    """
    Check cookie. If valid, redirect to index page, else redirect to login page. 
    If cookie has expired, remove all sessions of this user, and invalidates browser cookie. 
    """
    token = request.cookies.get('login_cookie')
    print(token)
    ukey = get_user_key(token)
    if token == None:
        #print("No cookies received")
        return redirect(url_for('login_page'))
    else:
        #print("received cookie")
        #print(token)
        query = DS.query(kind='session')
        query.add_filter('Token', '=', token)
        query.add_filter('UserID','=',ukey)
        results = list(query.fetch())
        if len(results) == 0:
            #print("No cookies in datastore")
            return redirect(url_for('login_page'))
        elif results[0]['Expires']>datetime.datetime.now(timezone.utc):
            #print("Cookie verified")
            return redirect(url_for('index'))
        else:
            query2 = DS.query(kind="session")
            query2.add_filter('UserID','=',ukey)
            sessions = list(query.fetch())
            for session in sessions:
                DS.delete(session.key)
            resp = make_response(render_template("login.html"))
            #domain = "lab3-dot-amiable-reducer-251721.appspot.com"
            resp.set_cookie("login_cookie", value='', max_age=10, domain=domain, secure=True)
            return resp


@app.route('/register', methods=['POST'])
def register():
    username = request.form['username'].strip()
    password = request.form['password'].strip()
    entity = datastore.Entity(key=DS.key('user'))
    pwd = bcrypt.hashpw(password.encode(), bcrypt.gensalt(5))
    entity.update({'Username': username, 'Password': pwd})
    DS.put(entity)
    return redirect(url_for('login'), code="307")


@app.route('/oidcauth', methods=['GET'])
def oidcauth():
    state = request.args['state']
    code = request.args['code']
    session_state = request.args['session_state']
    client_id = DS.get(DS.key('secret', oidc))['Client ID']
    client_secret = DS.get(DS.key('secret', oidc))['Client Secret']
    redirect_uri = "https://" + domain + "/oidcauth"
    #check if state matches
    oidc_cookie = request.cookies.get('oidc_cookie')
    print(oidc_cookie)
    json_oidc = json.loads(oidc_cookie)
    browser_state = json_oidc['state']
    if browser_state != state:
        print("State mismatch")
        return "State mismatch"
    data = {
        "code" : code,
        "client_id" : client_id,
        "client_secret" : client_secret,
        "redirect_uri" : redirect_uri,
        "grant_type" : "authorization_code"
    }
    response = requests.post("https://www.googleapis.com/oauth2/v4/token",data)
    token = response.json()['id_token']
    jwt = unpack_jwt(token)
    #check if nonce matches
    nonce = jwt['nonce']
    browser_nonce = json_oidc['nonce']
    if browser_nonce != nonce:
        print("Nonce mismatch")
        return "Nonce mismatch"
    #get email, check if already exist in datastore
    email = jwt['email']
    query = DS.query(kind='user')
    query.add_filter('Username', '=', email)
    result = list(query.fetch())
    if len(result) == 0:
        #create in datastore if not already exist
        pwd = jwt['at_hash']
        key = DS.key('user')
        entity = datastore.Entity(key=key)
        entity.update({'Username': email, 'Password': pwd})
        DS.put(entity)
        query = DS.query(kind='user')
        query.add_filter('Username', '=', email)
        result = list(query.fetch())
    #create session and send cookie
    userKey = result[0].key;
    token = gen_token(10)
    exp = datetime.datetime.now(timezone.utc)
    exp = exp + timedelta(hours=1)
    entity = datastore.Entity(key=DS.key('session'))
    entity.update({'Token': token, 'Expires': exp, 'Domain': domain, 'UserID':userKey})
    DS.put(entity)
    #set-cookie header
    resp = make_response(render_template("index.html"))
    resp.set_cookie("login_cookie", value=token, max_age=3600, domain=domain, secure=True)
    return resp
    

@app.route('/login_page')
def login_page():
    #send cookie with oidc information
    response_type = "code"
    client_id = DS.get(DS.key('secret', oidc))['Client ID']
    scope = "openid email"
    state = gen_token(8)
    nonce = gen_token(6)
    redirect_uri = "https://" + domain + "/oidcauth"
    data = {
        'response_type' : response_type,
        'client_id' : client_id,
        'scope' : scope,
        'state' : state,
        'nonce' : nonce,
        'redirect_uri' : redirect_uri
    }
    #domain = "lab3-dot-amiable-reducer-251721.appspot.com"
    resp = make_response(render_template("login.html"))
    resp.set_cookie("oidc_cookie", value=json.dumps(data), max_age=3600, domain=domain, secure=True)
    return resp
    

@app.route('/index')
def index():
    return send_from_directory('static', 'index.html')



@app.route('/trans.js')
def loadJs():
    return send_from_directory('static', 'trans.js')


@app.route('/reg_page')
def reg_page():
    return send_from_directory('static', 'register.html')


@app.route('/policy')
def policy_page():
    return "privacy policy page"


@app.route('/service')
def service_page():
    return "service page"


if __name__ == '__main__':
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.
    app.run(host='127.0.0.1', port=8080, debug=True)
# [END gae_python37_app]

