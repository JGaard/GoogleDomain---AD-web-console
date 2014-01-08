#!/usr/bin/env python

from flask.ext.wtf import Form, TextField, TextAreaField, PasswordField, SubmitField,  validators, ValidationError, RadioField, Required
from models import db, User

class ContactForm(Form):
    name = TextField("Name",  [validators.Required()])
    email = TextField("Email",  [validators.Required(), validators.Email()])
    subject = TextField("Subject",  [validators.Required()])
    message = TextAreaField("Message",  [validators.Required()])
    submit = SubmitField("Send")
    
class NewUserForm(Form):
    username = TextField("Username",  [validators.Required('You must enter a Username (ex. JSmith)')])
    givenname = TextField("First name", [validators.Required('You must enter a First name')])
    familyname = TextField("Last name", [validators.Required('You must enter a Last name')])
    email = TextField("Email", [validators.Required('Please enter a valid domain email')])
    password_alpha = PasswordField("Password", [validators.Required('You must enter a Password'), validators.EqualTo('password_beta', message='Passwords must match')])
    password_beta = PasswordField("Confirm Password", [validators.Required('You must confirm your Password')])
    submit = SubmitField("Submit")
    
class EditUsersForm(Form):
    username = TextField("Username")
    givenname = TextField("First name")
    familyname = TextField("Last name")
    password_alpha = PasswordField("New Password")
    password_beta = PasswordField("Confirm Password")
    nicknames = TextField("Nicknames")
    submit = SubmitField("Submit")
    
class ForwardingForm(Form):
    newforwarder = TextField("Enter the email Address to be forwarded to:")
    submit = SubmitField("Submit")

class FiltersForm(Form):
    from_address = TextField("From:")
    to_address = TextField("To:")
    subject = TextField("Subject:")
    has_the_word = TextField("Has the Words:")
    does_not_have_the_word = TextField("Does NOT have the words:")
    label = TextField("Add a Label:")
    has_attachments = RadioField("Has Attachments:", choices=[("value1", "Yes"), ('value2', "No")], default='value2', validators=[Required()], coerce=unicode)
    archive = RadioField("To Be Archived:", choices=[("value1", "Yes"), ("value2", "No")], default="value2", validators=[Required()], coerce=unicode)
    mark_as_read= RadioField("To be Marked as Read:", choices=[("value1", "Yes"), ("value2", "No")], default="value2", validators=[Required()], coerce=unicode)
    submit = SubmitField("Sumbit")
    
class SignupForm(Form):
  firstname = TextField("First name",  [validators.Required("Please enter your first name.")])
  lastname = TextField("Last name",  [validators.Required("Please enter your last name.")])
  email = TextField("Email",  [validators.Required("Please enter your email address."), validators.Email("Please enter your email address.")])
  password = PasswordField('Password', [validators.Required("Please enter a password.")])
  submit = SubmitField("Create account")
 
  def __init__(self, *args, **kwargs):
    Form.__init__(self, *args, **kwargs)
 
  def validate(self):
    if not Form.validate(self):
      return False
     
    user = User.query.filter_by(email = self.email.data.lower()).first()
    if user:
      self.email.errors.append("That email is already taken")
      return False
    else:
      return True

class SigninForm(Form):
  email = TextField("Email",  [validators.Required("Please enter your email address."), validators.Email("Please enter your email address.")])
  password = PasswordField('Password', [validators.Required("Please enter a password.")])
  submit = SubmitField("Sign In")
   
  def __init__(self, *args, **kwargs):
    Form.__init__(self, *args, **kwargs)
 
  def validate(self):
    if not Form.validate(self):
      return False
     
    user = User.query.filter_by(email = self.email.data.lower()).first()
    if user and user.check_password(self.password.data):
      return True
    else:
      self.email.errors.append("Invalid e-mail or password")
      return False
    