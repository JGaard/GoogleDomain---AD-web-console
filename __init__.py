from flask import *

app = Flask(__name__)
 
app.secret_key = 'Plok2189'
 
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USERNAME"] = 'jamie@ninthstreet.org'
app.config["MAIL_PASSWORD"] = 'Harvey2Face'
 
from routes import mail
mail.init_app(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:iRoll20s@localhost/development'

from models import db
db.init_app(app)
 
import ninth_street_web_app.routes