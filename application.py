import os
from time import strftime, strptime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
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
    return render_template("index.html")

@app.route("/quote")
@login_required
def quote():
    return render_template("quote.html")

@app.route("/buy")
@login_required
def buy():
    return render_template("buy.html")

@app.route("/sell")
@login_required
def sell():
    return render_template("sell.html")

@app.route("/history")
@login_required
def history():
    return render_template("history.html")


@app.route("/api/portfolio")
@login_required
def portfolio_api():
    stocks = db.execute("SELECT symbol, shares FROM portfolio WHERE user_id = ?", session["user_id"])
    users = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = float("{:.2f}".format(users[0]['cash']))

    grand_total = cash
    rows = []
    for stock in stocks:
        if stock['shares'] > 0:
            result = lookup(stock['symbol'])
            price = float("{:.2f}".format(result['price'] * stock['shares']))
            total = cash + price
            grand_total = grand_total + price
            row = {
                "symbol": stock['symbol'],
                "shares": stock['shares'],
                "price": result['price'],
                "total_price":price,
                "grand_total": float("{:.2f}".format(total))
            }
            rows.append(row)
    return jsonify(rows)


@app.route("/api/quote")
@login_required
def quote_api():
    """Get stock quote."""
    quote = lookup(request.args.get("symbol"))
    if quote == None:
        return apology("Invalid Stock Name")
    return jsonify(quote)


@app.route("/api/buy", methods=["POST"])
@login_required
def buy_api():
    stock_symbol = request.json.get("symbol")
    stock_shares = request.json.get("shares")
    if stock_symbol == None or stock_symbol == '':
        return apology("Invalid stock symbol")
    elif  stock_shares == None or stock_shares == '' or int(stock_shares) < 1:
        return apology("Invalid stock count")
    else:
        rows = db.execute("SELECT cash FROM users WHERE id = ?", session['user_id'])
        stock_info = lookup(stock_symbol)
        stock_price = stock_info["price"]
        expenditure = stock_price * int(stock_shares)
        cash = rows[0]['cash']

        if cash < expenditure:
            return apology("Insufficient cash")
        else:
            initial_stocks = db.execute("SELECT * FROM portfolio WHERE user_id=? AND symbol=?", session['user_id'], stock_symbol)
            if len(initial_stocks) == 0:
                db.execute("INSERT INTO portfolio (user_id, symbol, shares) VALUES (?, ?, ?)", session['user_id'], stock_symbol, stock_shares)
            else:
                final_shares = initial_stocks[0]['shares'] + int(stock_shares)
                db.execute("UPDATE portfolio SET shares = ? WHERE user_id = ? AND symbol = ?", final_shares, session['user_id'], stock_symbol)
            cash_left = cash - expenditure
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash_left, session['user_id'])
            db.execute("INSERT INTO history (user_id, symbol, price, shares) VALUES (?, ?, ?, ?)", session['user_id'], stock_symbol, stock_price, int(stock_shares))
            return jsonify({"success": True})


@app.route("/api/sell", methods=["POST"])
@login_required
def sell_api():
    stock_symbol = request.json.get("symbol")
    stock_shares = request.json.get("shares")
    logs = db.execute("SELECT shares FROM portfolio WHERE user_id = ? AND symbol = ?", session['user_id'], stock_symbol)
    stock_count = logs[0]['shares']
    if stock_symbol == None or stock_symbol == '':
        return apology("Invalid stock symbol")
    elif stock_shares == None or stock_shares == '' or int(stock_shares) < 1:
        return apology("Invalid stock count")
    
    elif int(stock_shares) > stock_count:
        return apology("you dont have enough shares")
    else:
        stock = lookup(stock_symbol)
        stock_price = stock["price"]
        cash_earned = stock_price * int(stock_shares)
        initial_cash = db.execute("SELECT cash FROM users WHERE id = ?", session['user_id'])
        rows = db.execute("SELECT shares FROM portfolio WHERE user_id = ? AND symbol = ?", session['user_id'], stock_symbol)
        updated_shares = rows[0]['shares'] - int(stock_shares)
        final_cash = initial_cash[0]['cash'] + cash_earned
        db.execute("UPDATE users SET cash = ? WHERE id = ?", final_cash, session['user_id'])
        db.execute("UPDATE portfolio SET shares = ? WHERE user_id = ? AND symbol = ?", updated_shares, session['user_id'], stock_symbol)
        db.execute("INSERT INTO history (user_id, symbol, price, shares) VALUES (?, ?, ?, ?)",session['user_id'], stock_symbol, stock_price, -int(stock_shares))
        return jsonify({'success': True})


@app.route("/api/history")
@login_required
def history_api():
    """Show history of transactions"""
    histories = db.execute("SELECT * FROM history where user_id = ?", session['user_id'])
    return jsonify(histories)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password")
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


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        result = db.execute("SELECT username FROM users WHERE username = ?", username)
        # check if the username is blank or taken
        if len(result) == 1 or request.form.get("username") == '':
            return apology("Must provide a valid username")
        # check if the password and confirm password are same
        elif password != request.form.get("confirm-password"):
            return apology("Password does not match")
        else:
            hashed_password = generate_password_hash(password)
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_password)
            return redirect("/login")


@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def change():
    if request.method == 'GET':
        return render_template("change_password.html")
    else:
        old_password = request.form.get("old-password")
        users = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])
        correct_password_hash = users[0]["hash"]

        new_password = request.form.get("newpassword")
        confirm_password = request.form.get("confirm_password")
        new_password_hash = generate_password_hash(new_password)

        if check_password_hash(correct_password_hash, old_password) and new_password == confirm_password:
            db.execute("UPDATE users SET hash = ? WHERE id = ?", new_password_hash, session["user_id"])
            return redirect("/login")
        else:
            return apology("Passwords don't match")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=os.environ['PORT'])
