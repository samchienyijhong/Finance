import os
import re

from datetime import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd, check

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Show portfolio of stocks"""

    # Get current logged-in user's ID from stored session
    user_id = session["user_id"]

    if request.method == "POST":

        # Access from data
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide symbol", 400)

        # Buy
        if request.form.get("buy"):
            shares = request.form.get("shares")

            # Input should be positive interger
            if not check(shares):
                return apology("invalid shares", 400)

            # Call IEX API
            quote = lookup(symbol)
            if not quote:
                return apology("something went wrong", 400)
            price = quote["price"]

            # Do purchase
            cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[
                0]["cash"]
            purchase = int(shares) * price
            if cash < purchase:
                return apology("cannot afford this purchase", 400)
            cash = float(cash) - purchase
            db.execute("INSERT INTO transactions (user_id, symbol, shares, price, date, type) VALUES (?, ?, ?, ?, ?, 'BUY')",
                       user_id, symbol, shares, price, datetime.utcnow())
            db.execute("UPDATE users SET cash = ? WHERE id = ?",
                       cash, user_id)

            # Redirect user to home page
            return redirect("/")

        # Sell
        elif request.form.get("sell"):
            shares = request.form.get("shares")

            # Input should be positive interger
            if not check(shares):
                return apology("invalid shares", 400)
            shares_obtained = db.execute(
                "SELECT shares FROM stocks WHERE user_id = ? AND symbol = ?", user_id, symbol)[0]["shares"]
            if int(shares) > shares_obtained:
                return apology("invalid shares", 400)

            # Call IEX API
            quote = lookup(symbol)
            if not quote:
                return apology("something went wrong", 400)
            price = quote["price"]

            # Do Sale
            cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[
                0]["cash"]
            sale = int(shares) * price
            cash = float(cash) + sale
            db.execute("INSERT INTO transactions (user_id, symbol, shares, price, date, type) VALUES (?, ?, ?, ?, ?, 'SELL')",
                       user_id, symbol, shares, price, datetime.utcnow())
            db.execute("UPDATE users SET cash = ? WHERE id = ?",
                       cash, user_id)

            # Redirect user to home page
            return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)

    # Get data from database
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[
        0]["cash"]
    rows_transactions = db.execute(
        "SELECT symbol, SUM(CASE WHEN type = 'BUY' THEN shares ELSE shares * -1 END) AS sum_shares FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)

    # Organize data
    for row in rows_transactions:
        shares = row["sum_shares"]
        symbol = row["symbol"]
        if shares > 0:
            db.execute(
                "INSERT OR REPLACE INTO stocks (user_id, symbol, shares) VALUES (?, ?, ?)", user_id, symbol, shares)
        else:
            db.execute(
                "DELETE FROM stocks WHERE user_id = ? AND symbol = ?", user_id, symbol)

    # Stock list
    rows_stocks = db.execute("SELECT * FROM stocks WHERE user_id = ?", user_id)
    stocks = []
    total = cash
    for row in rows_stocks:
        symbol = row["symbol"]
        shares = row["shares"]
        price = lookup(symbol)["price"]
        value = shares * price
        stocks.append({"symbol": symbol, "shares": shares,
                       "price": price, "value": value})

        # Grand total
        total += value
    return render_template("index.html", stocks=stocks, cash=cash, total=total, usd=usd)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        # Access from data
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide symbol", 400)
        shares = request.form.get("shares")

        # Input should be positive interger
        if not check(shares):
            return apology("invalid shares", 400)

        # Call IEX API
        quote = lookup(symbol)
        if not quote:
            return apology("something went wrong", 400)
        price = quote["price"]

        # Get current logged-in user's ID from stored session
        user_id = session["user_id"]

        # Do purchase
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[
            0]["cash"]
        purchase = int(shares) * price

        if cash < purchase:
            return apology("cannot afford this purchase", 400)
        cash = float(cash) - purchase
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, date, type) VALUES (?, ?, ?, ?, ?, 'BUY')",
                   user_id, symbol, shares, price, datetime.utcnow())
        db.execute("UPDATE users SET cash = ? WHERE id = ?",
                   cash, user_id)

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("buy.html")


@ app.route("/history")
@ login_required
def history():
    """Show history of transactions"""

    # Get current logged-in user's ID from stored session
    user_id = session["user_id"]
    transactions = db.execute(
        "SELECT * FROM transactions WHERE user_id = ? ORDER BY date DESC", user_id)
    return render_template("history.html", transactions=transactions, usd=usd)


@ app.route("/login", methods=["GET", "POST"])
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
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("login.html")


@ app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@ app.route("/quote", methods=["GET", "POST"])
@ login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":

        # Access from data
        symbol = request.form.get("symbol")

        if not symbol:
            return apology("must provide symbol", 400)

        # Call IEX API
        quote = lookup(symbol)
        if not quote:
            return apology("invalid symbol", 400)

        return render_template("/quoted.html", quote=quote, usd=usd)

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("/quote.html")


@ app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Access from data
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Input Check
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        if len(rows) != 0:
            return apology("username already exists", 400)
        elif not username:
            return apology("must provide username", 400)
        elif not password:
            return apology("must provide password", 400)
        elif password != confirmation:
            return apology("password unmatches", 400)
        elif not re.match("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", password):
            return apology("password should contain minimum eight characters, at least one uppercase letter, one lowercase letter, one number and one special character", 400)

        # Insert data into database
        hash = generate_password_hash(password)
        db.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)

        # Redirect user to login page
        return redirect("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("/register.html")


@ app.route("/sell", methods=["GET", "POST"])
@ login_required
def sell():
    """Sell shares of stock"""

    # Get current logged-in user's ID from stored session
    user_id = session["user_id"]

    if request.method == "POST":

        # Access from data
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide symbol", 400)
        shares = request.form.get("shares")

        # Input should be positive interger
        if not check(shares):
            return apology("invalid shares", 400)
        shares_obtained = db.execute(
            "SELECT shares FROM stocks WHERE user_id = ? AND symbol = ?", user_id, symbol)[0]["shares"]
        if int(shares) > shares_obtained:
            return apology("invalid shares", 400)

        # Call IEX API
        quote = lookup(symbol)
        if not quote:
            return apology("something went wrong", 400)
        price = quote["price"]

        # Do Sale
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[
            0]["cash"]
        sale = int(shares) * price
        cash = float(cash) + sale
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, date, type) VALUES (?, ?, ?, ?, ?, 'SELL')",
                   user_id, symbol, shares, price, datetime.utcnow())
        db.execute("UPDATE users SET cash = ? WHERE id = ?",
                   cash, user_id)

        # Redirect user to home page
        return redirect("/")

    symbols = db.execute(
        "SELECT symbol FROM stocks WHERE user_id = ?", user_id)

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("sell.html", symbols=symbols)


@ app.route("/modify_password", methods=["GET", "POST"])
@ login_required
def modify_password():
    """Modify password"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Remember which user has logged in
        id = session["user_id"]

        # Access from data
        old = request.form.get("old")
        new = request.form.get("new")
        confirmation = request.form.get("confirmation")

        # Input check
        if not old:
            return apology("must provide old password", 403)
        elif not new:
            return apology("must provide new password", 403)
        elif not confirmation:
            return apology("must provide confirmation", 403)

        # Query database for user
        rows = db.execute("SELECT * FROM users WHERE id = ?", id)

        # Ensure username exists and old password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], old):
            return apology("invalid password", 403)

        # Ensure new password matches requirement
        elif new != confirmation:
            return apology("password unmatches", 403)
        elif not re.match("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", new):
            return apology("password should contain minimum eight characters, at least one uppercase letter, one lowercase letter, one number and one special character", 403)

        # Insert data into database
        hash = generate_password_hash(new)
        db.execute(
            "UPDATE users SET hash = ? WHERE id = ?", hash, id)

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("modify_password.html")


@ app.route("/add_cash", methods=["GET", "POST"])
@ login_required
def add_cash():
    """Add additional cash"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Remember which user has logged in
        id = session["user_id"]

        # Access from data
        cash_added = float(request.form.get("cash"))
        if not cash_added or cash_added <= 0:
            return apology("invalid input", 400)

        # Do add
        cash = db.execute("SELECT cash FROM users WHERE id = ?", id)[
            0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?",
                   cash + cash_added, id)

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("add_cash.html")
