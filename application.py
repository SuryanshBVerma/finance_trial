import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    portfolio = db.execute("SELECT * FROM portfolio WHERE id = ?", session["user_id"])
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = cash[0]["cash"]
    g_total = cash

    # looking up current price of each stock
    for share in portfolio:
        data = lookup(share["symbol"])
        share["price_per_share"] = data["price"]
        g_total = g_total + (data["price"] * share["no_of_shares"])

    return render_template("index.html",portfolio=portfolio,cash=cash,g_total=g_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        data = lookup(symbol)

        # ERROR CHECK

        # share numbers not an int:
        if not shares.isdigit():
            return apology("Invalid number of shares")

        # negavtive shares
        if int(shares) < 1:
            return apology("Invalid number of shares")

        # floating shares
        if not float(shares) - int(shares) == 0:
            return apology("Invalid number of shares")

        # data check
        if not data:
            return apology("Invalid Symbol")

        # Entering data into the database
        shares = int(shares)
        session_id = session["user_id"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session_id)
        cash = cash[0]["cash"]
        stock_price = data["price"] * shares

        # user cash availability
        if cash < stock_price:
            return apology("Cannot afford the number of shares at the current price")

        cash = cash - stock_price  # updating cash variable

        # buying the stock

        portfolio = db.execute("SELECT * FROM portfolio WHERE id = ?", session_id)

        # buying extra shares that the user already has:
        for row in portfolio:
            if row["symbol"] == data["symbol"]:
                db.execute("UPDATE portfolio SET no_of_shares = ?, price_per_share = ?, total_price = ? WHERE id = ? AND symbol = ?",
                            row["no_of_shares"] + shares, data["price"], (row["no_of_shares"] + shares) * data["price"], session_id, data["symbol"])
                db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session_id)  # updating cash in database
                db.execute("INSERT INTO buy VALUES(?,?,?,?,?,?)", session_id,
                            data["name"], data["symbol"], shares, data["price"], stock_price)
                return redirect("/")

        # buying new stock:

        # adding stock to portfolio
        db.execute("INSERT INTO portfolio VALUES(?,?,?,?,?,?)", session_id,
                    data["name"], data["symbol"], shares, data["price"], stock_price)
        #updating cash in database
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session_id) #updating cash in database
        # keeping record of buy
        db.execute("INSERT INTO buy VALUES(?,?,?,?,?,?)", session_id, data["name"],
                    data["symbol"], shares, data["price"], stock_price)
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    session_id = session["user_id"]
    sell = db.execute("SELECT * FROM sell WHERE id = ?", session_id)
    buy = db.execute("SELECT * FROM buy WHERE id = ?", session_id)
    return render_template("history.html", sell=sell,buy=buy)



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        data = lookup(symbol)

        # ERROR CHECK
        if not data:
            return apology("Invalid Symbol")

        return render_template("quoted.html", data=data)

    else:
        return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # ERROR CHECK -- Username

        # blank username:
        if not username:
            return apology("Please enter a username")

        # username already exsists:
        users = db.execute("SELECT username FROM users")
        for user in users:
            if username == user["username"]:
                return apology("Username already exsists")

        #username as spaces
        if(username.strip() == ""):
            return apology("Please enter a username")

        # ERROR CHECK -- Password

        # blank password
        if not password:
            return apology("Please enter a password")

        # password and confimation not match
        if password != confirmation:
            return apology("Passwords do not match")

        # REGISTERING THE INFORMATION

        # hashing password
        hashed = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        # entering the information in the database
        db.execute("INSERT INTO users (username,hash) VALUES(?,?)", username, hashed)
        return redirect("/login")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    session_id = session["user_id"]
    symbols = db.execute("SELECT symbol FROM portfolio WHERE id = ?", session_id)

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # ERROR CHECK -- symbol

        # symbol should be all letters
        if not symbol.isalpha():
            return apology("Invalid Symbol")
        # checking for symbols in database
        l =[]
        for row in symbols:
            l.append(row["symbol"])

        if not symbol in l:
            return apology("Invalid Symbol",2)

        # ERROR CHECK -- number of shares

        # shares should be all integers
        if not shares.isdigit():
            return apology("Invalid Number of shares", 10)
        # negative shares
        if int(shares) < 1:
            return apology("Invalid number of shares", 20)
        # floating shares
        if not float(shares) - int(shares) == 0:
            return apology("Invalid number of shares", 30)

        shares = int(shares)
        # sellability of shares:
        number_of_shares = db.execute("SELECT no_of_shares FROM portfolio WHERE id = ? AND symbol = ?", session_id, symbol)
        number_of_shares = number_of_shares[0]["no_of_shares"]

        if number_of_shares < shares:
            return apology("Cannot sell that many shares")

        cash = db.execute("SELECT cash FROM users WHERE id = ?", session_id)
        cash = cash[0]["cash"]
        portfolio = db.execute("SELECT * FROM portfolio WHERE id = ? AND symbol = ?", session_id, symbol)

        #selling complete shares:
        data = lookup(symbol)
        if portfolio[0]["no_of_shares"] == shares:
            db.execute("DELETE FROM portfolio WHERE symbol = ? AND id = ?", symbol , session_id)
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash + (data["price"] * shares), session_id)
            db.execute("INSERT INTO sell VALUES (?,?,?,?,?,?)", sesion_id, data["name"], data["symbol"], shares, data["price"], (data["price"] * shares))
            return redirect("/")
        #selling partial shares:
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash + (data["price"] * shares), session_id)
        db.execute("UPDATE portfolio SET no_of_shares = ?, price_per_share = ?, total_price = ? WHERE symbol = ? AND id = ?",
                    portfolio[0]["no_of_shares"] - shares, data["price"],(portfolio[0]["no_of_shares"] - shares) * data["price"], symbol, session_id)
        db.execute("INSERT INTO sell VALUES (?,?,?,?,?,?)", session_id,
                    data["name"], data["symbol"], shares, data["price"], (data["price"] * shares))
        return redirect("/")
    else:
        return render_template("sell.html", symbols=symbols)

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
