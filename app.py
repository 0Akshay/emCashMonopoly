import os
from flask import Flask, flash, redirect, render_template, request, session
from cs50 import SQL
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

# From other file, might be optional
import urllib.parse
import requests
from functools import wraps

app = Flask(__name__)

app.config["TEMPLATES_AUTO_RELOAD"] = True

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///emcash.db")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Functions from the other file
def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"


def gamestatuscheck():
        return int((db.execute("SELECT * FROM gamestatus"))[0]["status"])


# Application Begins
@app.route("/")
def index():
    return render_template("login.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if gamestatuscheck() == -1:
            flash("Game stopped by admin")
            return render_template("login.html")

    # Forget any user_id
    session.clear()

    username = request.form.get("username")
    password = request.form.get("password")

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            flash("Must provide username")
            return render_template("login.html", username=username, password=password)

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("Must provide password")
            return render_template("login.html", username=username, password=password)

        # Admin Check
        if username.lower() == "bank":
            flash("Please login via Bank Login")
            return render_template("login.html")

        # Query database for username
        rows = db.execute("SELECT * FROM players WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("Invalid username and/or password")
            return render_template("login.html", username=username, password=password)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/home")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/signup", methods=["GET", "POST"])
def signup():

    if gamestatuscheck() == 1:
            flash("Game in progress. Can't sign up!")
            return render_template("login.html")

    if request.method == "GET":
        return render_template("signup.html")

    name = request.form.get("name")
    username = request.form.get("username")
    password = request.form.get("password")
    confirmpassword = request.form.get("confirmpassword")

    # code from finance
    if (name == "" or username == "" or password == "" or confirmpassword == ""):
        flash("Incomplete details!")
        return render_template("signup.html", name=name, username=username, password=password, confirmpassword=confirmpassword)

    # Admin Check
    if username.lower() == "bank":
        flash("Unauthorized!")
        return render_template("login.html")

    elif not password == confirmpassword:
        flash("Passwords don't match!")
        return render_template("signup.html", name=name, username=username)

    data = db.execute("SELECT * FROM players WHERE username = ?", username)

    if (not len(data) == 0):
        flash("username already taken!")
        return render_template("signup.html", name=name, username=username, password=password, confirmpassword=confirmpassword)

    db.execute("INSERT INTO players (name, username, hash, money) VALUES (?,?,?,?)", name, username, generate_password_hash(password), 1500)

    rows = db.execute("SELECT * FROM players WHERE username = ?", username)

    # session["user_id"] = rows[0]["id"]
    flash('Registeration Successful! You can log in.')
    return redirect("/signup")
    # end code form finance


@app.route("/home", methods=["GET", "POST"])
@login_required
def home():

    if gamestatuscheck() == -1:
            flash("Game stopped by admin")
            return render_template("login.html")

    if request.method == "GET":
        info = db.execute("SELECT * FROM players WHERE id = ?", session["user_id"])

        name = info[0]["name"]
        username = info[0]["username"]
        money = info[0]["money"]

        players = db.execute("SELECT username, name FROM players")

        # Removes the current user form the list
        for row in players:
            if row["username"] == username:
                players.remove(row)


        mytransactionsinfo = db.execute("SELECT * FROM transactions WHERE fromid = ? or toid = ? ORDER BY datetime DESC LIMIT 5", session["user_id"], session["user_id"])

        for row in mytransactionsinfo:
            if row["fromid"] == session["user_id"]:
                row["status"] = "SENT"
            elif row["toid"] == session["user_id"]:
                row["status"] = "RECEIVED"
            row["amount"] = usd(row["amount"])

        transactionsinfo = db.execute("SELECT * FROM transactions ORDER BY datetime DESC LIMIT 5")

        for row in transactionsinfo:
            row["amount"] = usd(row["amount"])

        return render_template("home.html", name=name, money=usd(money), mytransactions=mytransactionsinfo, transactions=transactionsinfo, players=players)

    payusername = request.form.get("payusername")
    payamount = request.form.get("payamount")

    # Checking the values
    info = db.execute("SELECT * FROM players WHERE username = ?", payusername)

    if (not len(info) == 1):
        flash("Invalid Payee Name")
        return redirect("/home")

    if (payamount == ""):
        flash("Empty amount field!")
        return redirect("/home")

    try:
        val = float(payamount)
    except ValueError:
        flash("Invalid Amount1")
        return redirect("/home")

    if (float(payamount) <= 0):
        flash("Invalid Amount entered2")
        return redirect("/home")

    payamount = round(float(payamount), 2)

    info = db.execute("SELECT money, username FROM players WHERE id = ?", session["user_id"])

    if (float(payamount) > float(info[0]["money"])):
        flash("Insufficient funds!")
        return redirect("/home")

    if (payusername == info[0]["username"]):
        flash("Pay to self not allowed!")
        return redirect("/home")


    # Entering the transaction
    db.execute("UPDATE players SET money = money - ? WHERE id = ?", payamount, session["user_id"])

    db.execute("UPDATE players SET money = money + ? WHERE username = ?", payamount, payusername)

    payeeinfo = db.execute("SELECT id, username, name FROM players WHERE id =?", session["user_id"])
    beneficiaryinfo = db.execute("SELECT id, username, name FROM players WHERE username = ?", payusername)

    db.execute("INSERT INTO transactions (fromid, fromusername, fromname, toid, tousername, toname, amount) VALUES (?,?,?,?,?,?,?)", payeeinfo[0]["id"], payeeinfo[0]["username"], payeeinfo[0]["name"], beneficiaryinfo[0]["id"], beneficiaryinfo[0]["username"], beneficiaryinfo[0]["name"], payamount)

    flash("Transaction Successful!")
    return redirect("/home")


@app.route("/mytransactions")
@login_required
def mytransactions():

    if gamestatuscheck() == -1:
                flash("Game stopped by admin")
                return render_template("login.html")

    mytransactionsinfo = db.execute("SELECT * FROM transactions WHERE fromid = ? or toid = ? ORDER BY datetime DESC", session["user_id"], session["user_id"])

    for row in mytransactionsinfo:
        if row["fromid"] == session["user_id"]:
            row["status"] = "SENT"
        elif row["toid"] == session["user_id"]:
            row["status"] = "RECEIVED"
        row["amount"] = usd(row["amount"])

    return render_template("mytransactions.html", mytransactions=mytransactionsinfo)


@app.route("/transactions")
@login_required
def transactions():

    if gamestatuscheck() == -1:
            flash("Game stopped by admin")
            return render_template("login.html")

    transactionsinfo = db.execute("SELECT * FROM transactions ORDER BY datetime DESC")

    for row in transactionsinfo:
        row["amount"] = usd(row["amount"])

    return render_template("transactions.html", transactions=transactionsinfo)

@app.route("/banklogin", methods=["GET", "POST"])
def banklogin():
    # Forget any user_id
    session.clear()

    username = request.form.get("username")
    password = request.form.get("password")

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            flash("Must provide username")
            return render_template("banklogin.html", username=username, password=password)

        # Ensure username is bank
        if not request.form.get("username").lower() == "bank":
            flash("Username and/or password incorrect!")
            return render_template("banklogin.html", username=username, password=password)

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("Must provide password")
            return render_template("banklogin.html", username=username, password=password)

        # Query database for username
        rows = db.execute("SELECT * FROM players WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("Invalid username and/or password")
            return render_template("banklogin.html", username=username, password=password)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/bankhome")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("banklogin.html")


@app.route("/bankhome", methods=["GET", "POST"])
@login_required
def bankhome():
    if request.method == "GET":

        bankid = db.execute("SELECT id FROM players WHERE username = ?", "BANK")[0]["id"]

        if not session["user_id"] == bankid:
            session.clear()
            flash("Unauthorized")
            return redirect("/login")

        gamestatus = "checking"
        if gamestatuscheck() == 1:
            gamestatus = "In Progress"
        elif gamestatuscheck() == -1:
            gamestatus = "Stopped"

        players = db.execute("SELECT * FROM players")

        for player in players:
            player["money"] = usd(player["money"])

        # from home.html
        # Removes the current user form the list
        for row in players:
            if row["username"] == "BANK":
                players.remove(row)

        mytransactionsinfo = db.execute("SELECT * FROM transactions WHERE fromid = ? or toid = ? ORDER BY datetime DESC LIMIT 5", session["user_id"], session["user_id"])

        for row in mytransactionsinfo:
            if row["fromid"] == session["user_id"]:
                row["status"] = "SENT"
            elif row["toid"] == session["user_id"]:
                row["status"] = "RECEIVED"
            row["amount"] = usd(row["amount"])

        transactionsinfo = db.execute("SELECT * FROM transactions ORDER BY datetime DESC LIMIT 5")

        for row in transactionsinfo:
            row["amount"] = usd(row["amount"])
        # end from home.html

        rawplayers = db.execute("SELECT * FROM players")

        return render_template("bankhome.html", gamestatus=gamestatus, players=players, rawplayers=rawplayers, mytransactions=mytransactionsinfo, transactions=transactionsinfo)


@app.route("/togglegamestatus", methods=["POST"])
@login_required
def togglegamestatus():

    bankid = db.execute("SELECT id FROM players WHERE username = ?", "BANK")[0]["id"]

    if not session["user_id"] == bankid:
        session.clear()
        flash("Unauthorized")
        return redirect("/login")

    db.execute("UPDATE gamestatus SET status = -status WHERE id = ?", session["user_id"])

    return redirect("/bankhome")



@app.route("/bankpay", methods=["POST"])
@login_required
def bankpay():
    bankid = db.execute("SELECT id FROM players WHERE username = ?", "BANK")[0]["id"]

    if not session["user_id"] == bankid:
        session.clear()
        flash("Unauthorized")
        return redirect("/login")

    payusername = request.form.get("payusername")
    payamount = request.form.get("payamount")

    # Checking the values
    info = db.execute("SELECT * FROM players WHERE username = ?", payusername)

    if (not len(info) == 1):
        flash("Invalid Payee Name")
        return redirect("/bankhome")

    if (payamount == ""):
        flash("Empty amount field!")
        return redirect("/bankhome")

    try:
        val = float(payamount)
    except ValueError:
        flash("Invalid Amount 1")
        return redirect("/bankhome")

    if (float(payamount) <= 0):
        flash("Invalid Amount entered 2")
        return redirect("/bankhome")

    payamount = round(float(payamount), 2)

    info = db.execute("SELECT money, username FROM players WHERE id = ?", session["user_id"])

    if (float(payamount) > float(info[0]["money"])):
        flash("Insufficient funds!")
        return redirect("/bankhome")

    if (payusername == info[0]["username"]):
        flash("Pay to self not allowed!")
        return redirect("/bankhome")

    # Entering the transaction
    db.execute("UPDATE players SET money = money - ? WHERE id = ?", payamount, session["user_id"])

    db.execute("UPDATE players SET money = money + ? WHERE username = ?", payamount, payusername)

    payeeinfo = db.execute("SELECT id, username, name FROM players WHERE id =?", session["user_id"])
    beneficiaryinfo = db.execute("SELECT id, username, name FROM players WHERE username = ?", payusername)

    db.execute("INSERT INTO transactions (fromid, fromusername, fromname, toid, tousername, toname, amount) VALUES (?,?,?,?,?,?,?)", payeeinfo[0]["id"], payeeinfo[0]["username"], payeeinfo[0]["name"], beneficiaryinfo[0]["id"], beneficiaryinfo[0]["username"], beneficiaryinfo[0]["name"], payamount)

    flash("Transaction Successful!")
    return redirect("/bankhome")


@app.route("/setbalance", methods=["POST"])
@login_required
def setbalance():
    bankid = db.execute("SELECT id FROM players WHERE username = ?", "BANK")[0]["id"]

    if not session["user_id"] == bankid:
        session.clear()
        flash("Unauthorized")
        return redirect("/login")

    setbalanceusername = request.form.get("setbalanceusername")
    setbalance = request.form.get("setbalance")

    # Checking the values
    info = db.execute("SELECT * FROM players WHERE username = ?", setbalanceusername)

    if (not len(info) == 1):
        flash("Invalid Payee Name")
        return redirect("/bankhome")

    if (setbalance == ""):
        flash("Empty amount field!")
        return redirect("/bankhome")

    try:
        val = float(setbalance)
    except ValueError:
        flash("Invalid Amount 1")
        return redirect("/bankhome")

    if (float(setbalance) <= 0):
        flash("Invalid Amount entered 2")
        return redirect("/bankhome")

    # Entering the transaction
    db.execute("UPDATE players SET money = ? WHERE username = ?", setbalance, setbalanceusername)

    flash("Balance set successfully!")
    return redirect("/bankhome")


@app.route("/removeplayer", methods=["POST"])
@login_required
def removeplayer():

    bankid = db.execute("SELECT id FROM players WHERE username = ?", "BANK")[0]["id"]

    if not session["user_id"] == bankid:
        session.clear()
        flash("Unauthorized")
        return redirect("/login")

    removeusername = request.form.get("removeusername")

    if removeusername == "BANK":
        flash("Cannot remove the admin!")
        return redirect("/bankhome")

    # Checking the values
    info = db.execute("SELECT * FROM players WHERE username = ?", removeusername)

    if (not len(info) == 1):
        flash("Invalid Payee Name")
        return redirect("/bankhome")

    db.execute("DELETE FROM players WHERE username = ?", removeusername)
    flash("Player removed!")
    return redirect("/bankhome")


@app.route("/confirmrestartgame", methods=["GET","POST"])
@login_required
def confirmrestartgame():
    bankid = db.execute("SELECT id FROM players WHERE username = ?", "BANK")[0]["id"]

    if not session["user_id"] == bankid:
        session.clear()
        flash("Unauthorized")
        return redirect("/login")

    if request.method == "GET":
        return render_template("confirmrestartgame.html")

    db.execute("UPDATE gamestatus SET status = -1 WHERE id = ?", session["user_id"])
    db.execute("DELETE FROM transactions")
    db.execute("UPDATE players SET money = 1500")

    flash("Game restarted! Please toggle start.")
    return redirect("/bankhome")


@app.route("/confirmfactoryresetgame", methods=["GET","POST"])
@login_required
def confirmfactoryresetgame():
    bankid = db.execute("SELECT id FROM players WHERE username = ?", "BANK")[0]["id"]

    if not session["user_id"] == bankid:
        session.clear()
        flash("Unauthorized")
        return redirect("/login")

    if request.method == "GET":
        return render_template("confirmfactoryresetgame.html")

    db.execute("UPDATE gamestatus SET status = -1 WHERE id = ?", session["user_id"])
    db.execute("DELETE FROM transactions")
    db.execute("DELETE FROM players WHERE username != ?", "BANK")

    flash("Factory reset complete!")
    return redirect("/bankhome")


@app.route("/bankmytransactions", methods=["GET","POST"])
@login_required
def bankmytransactions():
    bankid = db.execute("SELECT id FROM players WHERE username = ?", "BANK")[0]["id"]

    if not session["user_id"] == bankid:
        session.clear()
        flash("Unauthorized")
        return redirect("/login")

    if request.method == "GET":

        mytransactionsinfo = db.execute("SELECT * FROM transactions WHERE fromid = ? or toid = ? ORDER BY datetime DESC", session["user_id"], session["user_id"])

        for row in mytransactionsinfo:
            if row["fromid"] == session["user_id"]:
                row["status"] = "SENT"
            elif row["toid"] == session["user_id"]:
                row["status"] = "RECEIVED"
            row["amount"] = usd(row["amount"])

        return render_template("bankmytransactions.html", mytransactions=mytransactionsinfo)

    return redirect("/bankhome")


@app.route("/banktransactions", methods=["GET","POST"])
@login_required
def banktransactions():
    bankid = db.execute("SELECT id FROM players WHERE username = ?", "BANK")[0]["id"]

    if not session["user_id"] == bankid:
        session.clear()
        flash("Unauthorized")
        return redirect("/login")

    if request.method == "GET":

        transactionsinfo = db.execute("SELECT * FROM transactions ORDER BY datetime DESC")

        for row in transactionsinfo:
            row["amount"] = usd(row["amount"])

        return render_template("banktransactions.html", transactions=transactionsinfo)

    return redirect("/bankhome")
