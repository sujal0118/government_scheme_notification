from flask import Flask, jsonify, render_template , request, redirect, url_for,session,flash
from flask_wtf import FlaskForm
from wtforms import DecimalField, StringField,PasswordField,EmailField,SubmitField, IntegerField, RadioField,SelectField,TextAreaField
from wtforms.validators import DataRequired, Email,ValidationError,NumberRange,Regexp
import bcrypt
from flask_mysqldb import MySQL
from email_validator import validate_email, EmailNotValidError
from datetime import timedelta
from functools import wraps
from flask_socketio import SocketIO, emit
import nltk
from weasyprint import HTML
from nltk.corpus import stopwords
from collections import Counter
import string
import io
import os





app=Flask(__name__ ,template_folder='D:/Government notification system/website/templates')
socketio = SocketIO(app)








# logging.basicConfig(level=logging.DEBUG)

#MySQL configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB']='scheme'
app.config['MYSQL_PORT'] = 3306
app.secret_key = os.environ.get('SECRET_KEY', '@0118')

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

mysql=MySQL(app)


#register

class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(),Regexp(r'^[A-Za-z\s]+$', message="Name must contain only letters and spaces.")])
    email = EmailField('email', validators=[DataRequired(), Email()])
    phoneno = StringField('Number', validators=[DataRequired(), Regexp(r'^\d{10,13}$', message="Phone number must be between 10 and 13 digits.")])
    password = PasswordField('password', validators=[DataRequired()])
    age= IntegerField('age', validators=[DataRequired(), NumberRange(min=1, max=120)])
    gender = RadioField('Gender', choices=[('Male', 'Male'), ('Female', 'Female')], validators=[DataRequired()])
    caste = SelectField('Caste', choices=[('General', 'General'), ('SC', 'SC'), ('OBC', 'OBC'), ('ST', 'ST')], validators=[DataRequired()])
    location = SelectField('Location',  choices=[ ('Maharashtra', 'Maharashtra'), ('Karnataka', 'Karnataka'), ('Tamil Nadu', 'Tamil Nadu'),  ('Delhi', 'Delhi'),  ('Uttar Pradesh', 'Uttar Pradesh')], validators=[DataRequired()])
    occupation = SelectField( 'Occupation', choices=[('Student', 'Student'),  ('Retired', 'Retired'), ('Working', 'Working'), ('Gov Official', 'Gov Official')], validators=[DataRequired()])
    income= IntegerField('income', validators=[DataRequired(), NumberRange(min=1, max=10000000000)])
    
    
    submit=SubmitField("Register")
    def validate_email(self,field):
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM user WHERE email = %s", (field.data,))
        user = cur.fetchone()
        cur.close()
        if user:
            raise ValidationError("Email Already Taken")
    def validate_phoneno(self,field):
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM user WHERE phoneno = %s", (field.data,))
        user = cur.fetchone()
        cur.close()
        if user:
            raise ValidationError("Number Already Taken")

# login
class LoginForm(FlaskForm):
    email=EmailField('email', validators=[DataRequired(), Email()])
    password = PasswordField('password', validators=[DataRequired()])
    submit=SubmitField("Login")
    
# Admin Login Form
class AdminLoginForm(FlaskForm):
    admin_id = StringField('Admin ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField("Login")

#Add Scheme 
class SchemeForm(FlaskForm):
    scheme_name = StringField('Scheme Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired()])
    min_age = IntegerField('Minimum Age', validators=[DataRequired()])
    max_age = IntegerField('Maximum Age', validators=[DataRequired()])
    gender = SelectField('Gender', choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other'), ('All', 'All')], validators=[DataRequired()])
    caste = StringField('Caste', validators=[DataRequired()])
    min_income = DecimalField('Minimum Income', places=2, validators=[DataRequired()])
    max_income = DecimalField('Maximum Income', places=2, validators=[DataRequired()])
    submit = SubmitField('Add Scheme')


class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(),Regexp(r'^[A-Za-z\s]+$', message="Name must contain only letters and spaces.")])
    email = StringField('Email', validators=[DataRequired(), Email()])
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Submit')



 



@app.route('/register',methods=['GET','POST'] )
def register():
    form =RegisterForm()
    if form.validate_on_submit():
       name=form.name.data
       email=form.email.data
       phoneno=form.phoneno.data
    #    logging.debug(f'Registering user with phone number: {phoneno}')
       password=form.password.data
       age = form.age.data
       gender=form.gender.data
       caste = form.caste.data
       location = form.location.data
       occupation = form.occupation.data
       income = form.income.data
       
       hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
       
       # checking email
       try:
        valid=validate_email(email)
        email=valid.email
       except EmailNotValidError as err:
             return render_template('register.html',form=form,error=f"Invalid email{str(err)}")
        #storeing data
       cur=mysql.connection.cursor()
       try:
         cur.execute("INSERT INTO user(name,email,phoneno,password,age,gender,caste,location,occupation,income) VALUES (%s, %s,%s,%s,%s,%s,%s,%s,%s,%s)",(name,email,phoneno,hashed_password,age,gender,caste,location,occupation,income))
         mysql.connection.commit()
         
         cur.close()
         flash("Registration successful")
         return redirect(url_for('login'))
       except Exception as e:
         mysql.connection.rollback()
         cur.close()
         flash("Registration unsuccessful")
         return render_template('register.html',form=form,error=f"an error occurred:{str(e)}")
 
    return render_template('register.html',form=form)
     
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login')) 
        return f(*args, **kwargs)
    return decorated_function

def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM user WHERE email=%s", [email])
        user = cur.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[4].encode('utf-8')):
            session["user_id"] = user[0]
            flash("Login Successful.")
            # # Emit a login notification
            # socketio.emit('notification', {'message': 'Welcome! Checking your eligibility for schemes...'}, room=user[0])
            return redirect(url_for('index')) 
        else:
            flash("Login Failed. Please check your Email and Password")
            return redirect(url_for('login'))
    return render_template('login.html', form=form)

@app.route('/')
def index():
    check_eligibility()
    if'user_id'in session:
        return render_template('index.html',logged_in=True)
    else:
     return render_template('index.html',logged_in=False)




 
@app.route('/scheme')
@login_required
def scheme():
    logged_in = 'user_id' in session
    if logged_in:
        cur = mysql.connection.cursor()
        cur.execute("SELECT scheme_name, description, min_age, max_age, min_income, max_income, caste, gender, location FROM schemes")
        schemes = cur.fetchall()
        cur.close()
        return render_template('scheme.html', logged_in=logged_in, schemes=schemes)
    else:
        return redirect(url_for('login'))

@app.route('/notification')
@login_required
def notification():
    logged_in = 'user_id' in session
    if 'user_id' in session:
        user_id = session['user_id']
        cur = mysql.connection.cursor()

        # Fetch notification history for the user
        cur.execute("SELECT message, created_at FROM notification_history WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
        notifications = cur.fetchall()
        
        cur.close()
        return render_template('notification.html', notifications=notifications,logged_in=logged_in)
    return redirect(url_for('login'))
    
    
@app.route('/check_eligibility', methods=['GET', 'POST'])
@login_required
def check_eligibility():
    if 'user_id' in session:
        user_id = session['user_id']
        cur = mysql.connection.cursor()

        try:
            # Get the user's data, including location
            cur.execute("SELECT age, caste, income, gender, location FROM user WHERE user_id = %s", (user_id,))
            user_info = cur.fetchone()

            if not user_info:
                flash("User data not found.")
                return redirect(url_for('dashboard'))

            # Check eligibility with dynamic range conditions and include location
            query = """
                SELECT * 
                FROM schemes 
                WHERE %s BETWEEN min_income AND max_income
                AND %s BETWEEN min_age AND max_age
                AND (caste = %s OR caste LIKE CONCAT('%%', %s, '%%'))
                AND (gender = %s OR gender = 'Any')
                AND (location = %s OR location = 'All')
            """
            cur.execute(query, (user_info[2], user_info[0], user_info[1], user_info[1], user_info[3], user_info[4]))
            eligible_schemes = cur.fetchall()

            # Check if there are eligible schemes and format them as a numbered list
            if eligible_schemes:
                scheme_list = [f"{index + 1}. {scheme[1]}" for index, scheme in enumerate(eligible_schemes)]  # Assuming 2nd column is scheme name
                message = "You are eligible for these schemes:"+"<br>" + "<br>".join(scheme_list)
            else:
                message = "No schemes found for you, check after some time."

            # Emit the notification to the user
            socketio.emit('notification', {'message': message}, room=user_id)

            # Store the notification in history
            cur.execute("INSERT INTO notification_history (user_id, message) VALUES (%s, %s)", (user_id, message))
            mysql.connection.commit()

            flash(message)
        except Exception as e:
            flash(f"An error occurred: {str(e)}")
        finally:
            cur.close()

        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))





@app.route('/about')
def about():
  logged_in = 'user_id' in session
  return render_template('about.html', logged_in=logged_in)

nltk.download('stopwords')


def extract_keywords(text):
    text = text.lower()
    
    text = text.translate(str.maketrans('', '', string.punctuation))
    
    words = text.split()
    stop_words = set(stopwords.words('english'))
    keywords = [word for word in words if word not in stop_words]
    return keywords
    
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    logged_in = 'user_id' in session
    form = ContactForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        message = form.message.data
        keywords = extract_keywords(message)
        keywords_str = ', '.join(keywords)  # Convert list to string

        # Insert feedback into the database
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO feedback (name, email, message, keywords) VALUES (%s, %s, %s, %s)", (name, email, message, keywords_str))
        mysql.connection.commit()
        cur.close()

        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('contact'))
    
    return render_template('contact.html', form=form, logged_in=logged_in)
  
nltk.download('stopwords')


def extract_keywords(text):
    text = text.lower() 
    text = text.translate(str.maketrans('', '', string.punctuation)) 
    words = text.split() 
    stop_words = set(stopwords.words('english'))  
    keywords = [word for word in words if word not in stop_words]  
    return keywords

@app.route('/dashboard')
@login_required
def dashboard():
    if  'user_id' in session:
        cur=mysql.connection.cursor()
        cur.execute("SELECT * FROM user WHERE user_id=%s",[session['user_id']])
        user=cur.fetchone()
        cur.close()
        
        if user:
         return render_template('dashboard.html',user=user)

    return redirect('register.html')

@app.route('/submit_rating', methods=['POST'])
@login_required 
def submit_rating():
    data = request.get_json()  
    rating = data.get('rating') 

    if rating is None:
        return jsonify({"success": False, "message": "Rating not provided"}), 400

    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"success": False, "message": "User not authenticated"}), 401

   
    try:
        rating = int(rating)
        if rating < 1 or rating > 5:
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({"success": False, "message": "Invalid rating value"}), 400

    cursor = mysql.connection.cursor()  
    try:
        
        cursor.execute("UPDATE user SET rating = %s WHERE user_id = %s", (rating, user_id))
        mysql.connection.commit()  
        return jsonify({"success": True}), 200
    except Exception as e:  
        print("Error:", e)
        mysql.connection.rollback()
        return jsonify({"success": False, "message": "Database error"}), 500
    finally:
        cursor.close()

@app.route('/logout')
@login_required
def  logout():
    session.pop('user_id',None)
    flash("You have been successfully logged out.")
    return redirect(url_for('index'))




@app.route('/admin_login',methods=['GET','POST'])
def  admin_login():
    form=AdminLoginForm()
    if form.validate_on_submit():
        admin_id=form.admin_id.data
        password=form.password.data
        cur=mysql.connection.cursor()
        cur.execute("SELECT * FROM admin WHERE admin_id=%s ",[admin_id])
        admin=cur.fetchone()
        cur.close()
        
        if  admin and admin[2]==password:
            session["id"]=admin[0]
            flash("Admin login successful ")
            return redirect(url_for('admin'))
        else:
            flash("Admin login failed")
            return redirect(url_for('admin_login'))
    return render_template('admin_login.html',form=form)  

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'id' in session:
        cur = mysql.connection.cursor()

        # Fetch admin details
        cur.execute("SELECT * FROM admin WHERE id=%s", [session['id']])
        admin = cur.fetchone()

        # Fetch all users
        cur.execute("SELECT * FROM user")
        users = cur.fetchall()
        #feedback
        cur.execute("SELECT * FROM feedback ORDER BY created_at DESC")
        feedback_list = cur.fetchall()

        # Scheme form for adding new schemes
        scheme_form = SchemeForm()

        if request.method == 'POST' and 'submit_scheme' in request.form:
         name = request.form['scheme_name']
         description = request.form['description']
         location = request.form['location']
         min_age = request.form['min_age']
         max_age = request.form['max_age']
         gender = request.form['gender']
         caste = request.form.get('caste')  # Nullable
         min_income = request.form.get('min_income')  # Nullable
         max_income = request.form.get('max_income')  # Nullable

         # Insert the new scheme into the database
         cur.execute(
             """INSERT INTO schemes 
             (scheme_name, description, location, min_age, max_age, gender, caste, min_income, max_income)
             VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
             (name, description, location, min_age, max_age, gender, caste, min_income, max_income)
         )
         mysql.connection.commit()
         flash('Scheme added successfully!')
         return redirect(url_for('admin'))

        # Fetch all schemes
        cur.execute("SELECT * FROM schemes")
        schemes = cur.fetchall()

        cur.close()

        return render_template('admin.html', admin=admin, users=users, schemes=schemes,feedback=feedback_list, scheme_form=scheme_form)
    else:
        return redirect(url_for('admin_login'))

@app.route('/delete_scheme/<int:id>', methods=['POST'])
def delete_scheme(id):
    if 'id' in session: 
        cur = mysql.connection.cursor()
        try:
            cur.execute("DELETE FROM schemes WHERE id = %s", (id,))
            mysql.connection.commit()
            flash('Scheme deleted successfully!')
        except Exception as e:
            mysql.connection.rollback()
            flash(f'An error occurred while deleting the scheme: {str(e)}')
        finally:
            cur.close()
        return redirect(url_for('admin'))
    else:
        return redirect(url_for('admin_login'))



@app.route('/admin_logout')
def  admin_logout():
    session.pop('id',None)
    flash("You have been successfully logged out.")
    session.clear()
    return redirect(url_for('index'))

# #white box testing.
# print("Current Working Directory:", os.getcwd())
# print("URL Map:")
# print(app.url_map)



if __name__ =='__main__':
    socketio.run(app,allow_unsafe_werkzeug=True ,debug=True)
    app.run(debug=True)
    
