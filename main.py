from flask import Flask, request, redirect, render_template
import cgi

app = Flask(__name__)

app.config['DEBUG'] = True      # displays runtime errors in the browser, too

# User signup path will validate the fields in the form and
# direct the user to the welcome confirmation message if
# all fields submitted are valid
@app.route("/signup", methods=['POST'] )
def signup():
    user_name = request.form['username']
    password = request.form['password']
    verify_password = request.form['verify_password']
    email = request.form['email']
    email_esc = cgi.escape(email, quote=True)
    
    # If all fields are empty
    if (user_name.strip() == "" and password.strip() == "" and verify_password.strip() == ""):
        error = "The username cannot be empty"
        error_type = "ALL"
        return render_template("signup.html",title="Signup", username=user_name,password=password,verify_password=verify_password,email=email,error=error,error_type=error_type)       

    # Validate the username
    if (user_name.strip() == "") or (not user_name) :
        error = "Username cannnot be empty"
        error_type = "USER"

        # Clear password fields for security reasons
        password = ""
        verify_password = ""

        return render_template("signup.html",title="Signup", username=user_name,password=password,verify_password=verify_password,email=email,error=error,error_type=error_type)
    elif " " in user_name.strip():
        user_name=""
        # Clear password fields for security reasons
        password = ""
        verify_password = ""
        error = "Username cannnot contain spaces"
        error_type = "USER"
        return render_template("signup.html",title="Signup", username=user_name,password=password,verify_password=verify_password,email=email,error=error,error_type=error_type)
    else:
        if (len(user_name.strip()) < 3) or (len(user_name.strip()) > 20):
            error = user_name + " is an invalid username, please enter a valid username" 
            user_name=""
            error_type = "USER"
            # Clear password fields for security reasons
            password = ""
            verify_password = ""
            return render_template("signup.html",title="Signup", username=user_name,password=password,verify_password=verify_password,email=email,error=error,error_type=error_type)

    # Validae the password
    if (password.strip() == "" or  verify_password.strip() == ""):
        error = "Passwords and confirmation password cannot be empty"
        error_type = "PASSWORD"
        password = ""
        verify_password = ""
        return render_template("signup.html",title="Signup", username=user_name,password=password,verify_password=verify_password,email=email,error=error,error_type=error_type)
    elif (password.strip() != verify_password.strip()):
        error = "Passwords don't match"
        error_type = "PASSWORD"
        password = ""
        verify_password = ""
        return render_template("signup.html",title="Signup", username=user_name,password=password,verify_password=verify_password,email=email,error=error,error_type=error_type)
    elif (len(password.strip()) < 3) or (len(password.strip()) > 20):
        error = "The password is invalid"
        error_type = "PASSWORD"
        password = ""
        verify_password = ""
        return render_template("signup.html",title="Signup", username=user_name,password=password,verify_password=verify_password,email=email,error=error,error_type=error_type)
    elif (len(verify_password.strip()) < 3) or (len(verify_password.strip()) > 20):
        error = "The password is invalid"
        error_type = "PASSWORD"
        password = ""
        verify_password = ""
        return render_template("signup.html",title="Signup", username=user_name,password=password,verify_password=verify_password,email=email,error=error,error_type=error_type)
    else:
        if (" " in password.strip() or " " in verify_password.strip()):
            error = "Passwords cannot contain spaces"
            error_type = "PASSWORD"
            password = ""
            verify_password = ""
            return render_template("signup.html",title="Signup", username=user_name,password=password,verify_password=verify_password,email=email,error=error,error_type=error_type)
        
    # Validate email address
    if (email_esc.strip() == ""):
        error = ""
        error_type = ""
    else:
        if (email_esc.find('@') < 0): 
            error = "The email address is invalid."
            error_type = "EMAIL"
            email = ""
            password = ""
            verify_password = ""
            return render_template("signup.html",title="Signup", username=user_name,password=password,verify_password=verify_password,email=email,error=error,error_type=error_type)
        if (email_esc.find('.') < 0): 
            error = "The email address is invalid."
            error_type = "EMAIL"
            email = ""
            password = ""
            verify_password = ""
            return render_template("signup.html",title="Signup", username=user_name,password=password,verify_password=verify_password,email=email,error=error,error_type=error_type)
        elif " " in email_esc.strip():
            error = "Email cannot contain spaces."
            error_type = "EMAIL"
            email = ""
            password = ""
            verify_password = ""
            return render_template("signup.html",title="Signup", username=user_name,password=password,verify_password=verify_password,email=email,error=error,error_type=error_type)
        else:
            if (len(email.strip()) < 3) or (len(email.strip()) > 20) and (email != ""):
                error = "The email address is invalid."
                error_type = "EMAIL"
                email = ""
                password = ""
                verify_password = ""
                return render_template("signup.html",title="Signup", username=user_name,password=password,verify_password=verify_password,email=email,error=error,error_type=error_type)    

    # Set the username once all tests for a valid username are met
    error = ""
    error_type = ""
    user_name_esc = cgi.escape(user_name, quote=True)     
    password_esc = cgi.escape(password, quote=True)
    verify_password_esc = cgi.escape(verify_password, quote=True)
    email_esc = cgi.escape(email, quote=True)

    # Render welcome page once all valid data criteria are met
    return render_template('welcome.html', title="Sign up", username=user_name_esc)

# This is the path whenever the user has successfully signed up.
@app.route("/welcome")
def welcome():
    user_name = request.form['username']
    if user_name.srip() != "":
        user_name_esc = cgi.escape(user_name, quote=True)
        return render_template('welcome.html', user_name=user_name)

@app.route("/")
def index():
    # Define the error and error type parameters
    encoded_error = request.args.get("error")
    encoded_error_type = request.args.get("error_type")
    return render_template('signup.html', title="Signup", error=encoded_error and cgi.escape(encoded_error, quote=True),error_type=encoded_error_type and cgi.escape(encoded_error_type, quote=True))

app.run()
