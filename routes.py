# -*- coding: utf-8 -*-

import foswiki_to_mediawiki_converter
import google_api
import gdata.apps.client
import LDAP
import settings

import base64
import os
import glob
import httplib2
import json
import urllib2
import urllib
from flask import *

from ninth_street_web_app import app
from forms import ContactForm, NewUserForm, EditUsersForm, ForwardingForm, FiltersForm, SignupForm

from apiclient.discovery import build
from oauth2client.client import *
from flask_oauth import OAuth
from flask.views import MethodView
from flask.ext.mail import Message, Mail
from functools import wraps
from werkzeug import secure_filename
from models import db, User

ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

mail = Mail()

app.CSRF_ENABLED = True
USERNAME=""

@app.route('/signup', methods=['GET', 'POST'])
def signup():
  form = SignupForm()
   
  if request.method == 'POST':
    if form.validate() == False:
      return render_template('signup.html', form=form)
    else:
        newuser = User(form.firstname.data, form.lastname.data, form.email.data, form.password.data)
        db.session.add(newuser)
        db.session.commit()
        
        session['email'] = newuser.email
        return redirect(url_for('profile'))
   
  elif request.method == 'GET':
    return render_template('signup.html', form=form)

@app.route('/profile')
def profile():
 
  if 'email' not in session:
    return redirect(url_for('signin'))
 
  user = User.query.filter_by(email = session['email']).first()
 
  if user is None:
    return redirect(url_for('signin'))
  else:
    return render_template('profile.html')

def login_required(test):
    @wraps(test)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return test(*args, **kwargs)
        else:
            flash('You need to login first.')
            return redirect(url_for('login'))
    return wrap 
 
#@app.route('/contact', methods=['GET', 'POST'])
#def contact():
#    form = ContactForm()
#    
#    if request.method == 'POST':
#        if form.validate() == False:
#            flash('All fields are required.')
#            return render_template('contact.html', form=form)
#        else:
#            msg = Message(form.subject.data, sender=SENDER, recipients=LIST_OF_RECIPIENTS)
#            msg.body = """
#            From: %s <%s>
#            %s
#            """ % (form.name.data, form.email.data, form.message.data)
#            mail.send(msg)
#            return render_template('contact.html', success=True)
# 
#    elif request.method == 'GET':
#        return render_template('contact.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    global USERNAME
    error = None
    
    if request.method == 'POST':
        USERNAME = request.form['username']
        if request.form['username'] != base64.b64decode(settings.encoded_google_domain_login) or request.form['password'] != base64.b64decode(settings.encoded_admin_pass):
            error = 'Invalid Credentials. Please try again or go away'
        else:
            session['logged_in'] = True
            return redirect(url_for('hello'))
    
    elif request.method == 'GET':    
        return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    session.pop('logged_in', None)
    flash("You logged out- See you next time")
    return redirect(url_for('login'))

@app.route('/newaccount', methods=['GET', 'POST'])
@login_required
def new_account_setup():
    form = NewUserForm()
    
    if request.method == 'POST':
        if form.validate() == False:
            flash('All fields are required.')
            return render_template('new_account_setup.html', domains_list=settings.list_of_local_domains, domains_tag=settings.local_domain_paths, form=form)
        else:
            gAPI = google_api.gAPI(request.form.get('org_domain'), form.username.data, form.password_alpha.data)
            gAPI.create_new_user(form.givenname.data, form.familyname.data)
            if request.form.get('ADcheckbox') == 'on':
                LDAP.addUser(str(form.username.data), str(form.givenname.data), str(form.familyname.data), str(form.email.data), str(form.password_alpha.data), str(request.form.get('org_name')))
                if request.form.get('hiddenGroupsList') == '':
                    pass
                else:
                    for group in eval(request.form.get('hiddenGroupsList')):
                        group_dn = group[0]
                        user_dn = 'CN=' + str(form.givenname.data) + ' ' + str(form.familyname.data) + ',OU=' + str(request.form.get('org_name')) + ',' + settings.local_DC
                        LDAP.addUsertoGroups(group_dn, user_dn)
            else:
                pass
            return redirect(url_for('home'))
    elif request.method == 'GET':
        return render_template('new_account_setup.html', domains_list=settings.list_of_local_domains, domains_tag=settings.local_domain_paths, form=form, ADorg_list=LDAP.retrieveADGroups())

@app.route('/index')
@login_required
def index():
    return render_template('index.html')

@app.route('/editgroups', methods=['GET', 'POST'])
def editgroups():
    
    if request.method == 'POST':
        username = request.args.get('user') 
        org_domain = request.args.get('org_domain')
        gAPI = google_api.gAPI(org_domain, username, "")
        user_chosen = json.loads(request.form['user_chosen'])
        domain_chosen = json.loads(request.form['domain_chosen'])
        relationTable = gAPI.setGroupRelation()
        
        if request.form['submit_state2'] == 'true':
            gAPI.addToGroup(relationTable[request.form['submit_value2']])
        
        if request.form['submit_state1'] == 'true':
            gAPI.removeFromGroup(relationTable[request.form['submit_value1']])
        
        return render_template('editgroups.html', username=username, org_domain=org_domain, userGroups=user_chosen, domainGroups=domain_chosen)
    
    if request.method == 'GET':
        username = request.args.get('user')
        org_domain = request.args.get('org_domain')
        gAPI = google_api.gAPI(org_domain, username, "")
        domainGroups=gAPI.retrieveDomainGroupNames()
        userGroups=gAPI.retriveUserGroupNames()
               
        return render_template('editgroups.html', username=username, org_domain=org_domain, userGroups=userGroups, domainGroups=domainGroups)
    
@app.route('/editforwarding', methods=['GET', 'POST'])
def editforwarding():
    form=ForwardingForm()
    
    if request.method == 'POST':
        gAPI = _initFromHTML(request.args.get('org_domain'), request.args.get('user'), "")
        
        if request.form['forwarderStatus'] == "NONE":
            gAPI.setForwardingSettings(False, gAPI.retrieveUserForwarding())     
            return render_template('editforwarding.html', org_domain=request.args.get('org_domain'), username=request.args.get('user'), forwarding=gAPI.retrieveUserForwarding(), form=form)
        
        if form.newforwarder.data not in gAPI.retrieveAllDomainAddresses():
            flash('You can only forward to an address in your domain. Addresses outside your domain need verification and must be set in a users account settings')
            return render_template('editforwarding.html', org_domain=request.args.get('org_domain'), username=request.args.get('user'), forwarding=gAPI.retrieveUserForwarding(), form=form)
        
        gAPI.setForwardingSettings(True, form.newforwarder.data)
        return render_template('editforwarding.html', org_domain=request.args.get('org_domain'), username=request.args.get('user'), forwarding=gAPI.retrieveUserForwarding(), form=form)
    
    if request.method == 'GET':
        gAPI = _initFromHTML(request.args.get('org_domain'), request.args.get('user'), "")
        return render_template('editforwarding.html', org_domain=request.args.get('org_domain'), username=request.args.get('user'), forwarding=gAPI.retrieveUserForwarding(), form=form)

@app.route('/editfilters', methods=['GET', 'POST'])
def editfilters():
    form = FiltersForm()
    
    if request.method == 'POST':
        gAPI = _initFromHTML(request.args.get('org_domain'), request.args.get('user'), "")
        parameters={}
        for fieldname, value in form.data.items():
            if value == "":
                parameters[fieldname] = None
            elif value =="value1":
                parameters[fieldname] = True
            elif value =="value2":
                parameters[fieldname] = False
            else:
                parameters[fieldname] = value
        
        gAPI.createNewFilter(**parameters)
            
        return render_template('editfilters.html', org_domain=request.args.get('org_domain'), username=request.args.get('user'), form=form)
    
    if request.method =='GET':
        return render_template('editfilters.html', org_domain=request.args.get('org_domain'), username=request.args.get('user'), form=form)
   
@app.route('/suspenduser', methods=['GET', 'POST'])
def suspend_user():
    user = request.args.get('user')
    org_domain = request.args.get('org_domain')
    gAPI = google_api.gAPI(org_domain, user, "")
    gAPI.suspend_user()
    message = "suspended"
    message_two = "If you would like to undo this action, simply navigate back to the list of users in the domain group and click the unsuspend button"
    return render_template('actionconfirm.html', message=message, message_two=message_two, user=user, org_domain=org_domain)

@app.route('/deleteuser', methods=['GET', 'POST'])
def delete_user():
    user = request.args.get('user')
    org_domain = request.args.get('org_domain')
    gAPI = google_api.gAPI(org_domain, user, "")
    gAPI.delete_user()
    message= "deleted"
    message_two = "This action CAN NOT be undone. The user has been erased from the system. If you would like to create a new account please click users at the top of the screen and follow the instructions"
    return render_template('actionconfirm.html', message=message, message_two=message_two, user=user, org_domain=org_domain)

@app.route('/unsuspenduser', methods=['GET', 'POST'])
def unsuspend_user():
    user = request.args.get('user')
    org_domain = request.args.get('org_domain')
    gAPI = google_api.gAPI(org_domain, user, "")
    gAPI.unsuspend_user()
    message= "unsuspended"
    message_two = "If you would like to undo this action, simply navigate back to the list of users in the domain group and click the suspend button, again."
    return render_template('actionconfirm.html', message=message, message_two=message_two, user=user, org_domain=org_domain)

@app.route('/editusers', methods=['GET', 'POST'])
@login_required
def editusers():
    form = EditUsersForm()
    
    user = request.args.get('user')
    org_domain = request.args.get('org_domain')
    
    if request.method == "POST":
            user = request.args.get('user')
            org_domain = request.args.get('org_domain')
            gAPI = google_api.gAPI(org_domain, user, "")
            
            if form.password_alpha.data == "":
                pass
            else:
                if form.password_alpha.data != form.password_beta.data:
                    flash('Passwords must match.')
                    return redirect(url_for('editusers', user=form.username.data, org_domain=org_domain))
                else:
                    gAPI.update_user_password(form.password_alpha.data)
        
            if request.form.get("clear_nicknames") == "clear":
                gAPI.delete_all_user_nicknames()
            else:
                for i in range(1, 7):
                    if nickname_len(request.form.get('nickname' + str(i))):
                        pass
                    else:
                        gAPI.create_nickname(request.form.get('nickname' + str(i)))
                
            gAPI.update_user_givenname(form.givenname.data)
            gAPI.update_user_familyname(form.familyname.data)
            gAPI.update_user_username(form.username.data)
            return redirect(url_for('editusers', user=form.username.data, org_domain=org_domain))

    if request.method == "GET":
        gAPI = google_api.gAPI(org_domain, user, "")
        return render_template('editusers.html', username=user, org_domain=org_domain,form=form, givenname=gAPI.get_firstname(), familyname=gAPI.get_lastname(), nicknames=gAPI.retrieve_nicknames())     


def nickname_len(nickname):
    if len(nickname) == 0:
        return True


@app.route('/hello')
@login_required
def hello():
    return render_template('hello.html', username=USERNAME)

@app.route('/')
@login_required
def home():
    return render_template('home.html')

@app.route('/test_page')
def test_page():
    return render_template('test.html')

@app.route('/userslist', methods=['GET', 'POST'])
@login_required
def userslist():
    if request.method == 'POST':
        org_domain = request.form['org_domain']
        return redirect(url_for('test_page'))
    return render_template('userslist.html', domains_list=settings.list_of_local_domains, domains_tag=settings.local_domain_paths)

@app.route('/userlist/display', methods=['GET','POST'])
@login_required
def user_list_display():
    org_domain = request.form['org_domain']
    gAPI = google_api.gAPI(org_domain, None, "")
    domain_users=gAPI.retrieve_domain_usernames()
    given_names=gAPI.retrieve_domain_givennames()
    family_names=gAPI.retrieve_domain_familynames()
    return render_template('user_list_display.html', domain_users=domain_users, given_names=given_names, family_names=family_names, org_domain=org_domain )


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        clear_output_folder()
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            output_file()
            clear_import_folder()
            return redirect(url_for('uploaded_file', filename=filename))
    return render_template('upload.html')


@app.route('/upload/<filename>')
@login_required
def uploaded_file(filename):
    file_path = os.path.join(OUTPUT_FOLDER,filename)
    with open(file_path) as f:
        return render_template('upload_output.html', f=f)
    
def _initFromHTML(org_domain, username, password):
    gAPI = google_api.gAPI(org_domain, username, password)
    return gAPI
    
