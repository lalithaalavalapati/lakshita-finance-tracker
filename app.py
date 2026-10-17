import os
import sqlite3
import calendar

from datetime import date, datetime
from functools import wraps

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

app = Flask(__name__)
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY", "change-this-secret-key"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "finance.db")


def get_db():
    conn = sqlite3.connect(
        DATABASE,
        timeout=30
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_db():
    conn = get_db()

    try:
        conn.execute("PRAGMA journal_mode = WAL")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS lakshita_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS lakshita_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                amount REAL NOT NULL,
                category TEXT NOT NULL,
                description TEXT,
                transaction_date TEXT NOT NULL,
                FOREIGN KEY(user_id)
                    REFERENCES lakshita_users(id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS lakshita_budgets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                monthly_limit REAL NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id)
                    REFERENCES lakshita_users(id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS lakshita_goals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                target REAL NOT NULL,
                saved REAL NOT NULL DEFAULT 0,
                target_months INTEGER NOT NULL DEFAULT 6,
                target_date TEXT,
                FOREIGN KEY(user_id)
                    REFERENCES lakshita_users(id)
            )
        """)

        # Existing goals table ki missing columns add cheyyadam
        goal_columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(lakshita_goals)"
            ).fetchall()
        }

        if "target_months" not in goal_columns:
            conn.execute("""
                ALTER TABLE lakshita_goals
                ADD COLUMN target_months INTEGER DEFAULT 6
            """)

        if "target_date" not in goal_columns:
            conn.execute("""
                ALTER TABLE lakshita_goals
                ADD COLUMN target_date TEXT
            """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS lakshita_goal_monthly_savings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                goal_id INTEGER NOT NULL,
                month_key TEXT NOT NULL,
                amount REAL NOT NULL DEFAULT 0,
                updated_at TEXT,
                FOREIGN KEY(user_id)
                    REFERENCES lakshita_users(id),
                FOREIGN KEY(goal_id)
                    REFERENCES lakshita_goals(id)
            )
        """)

        conn.commit()

    finally:
        conn.close()


init_db()
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first.", "error")
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped


def current_user_id():
    return session.get("user_id")


def get_month_range(month_offset=0):
    today = date.today()

    month_index = today.month - 1 + month_offset
    year = today.year + month_index // 12
    month = month_index % 12 + 1

    start = date(year, month, 1)
    end_day = calendar.monthrange(year, month)[1]
    end = date(year, month, end_day)

    return (
        start.isoformat(),
        end.isoformat(),
        f"{year}-{month:02d}"
    )


def get_totals(user_id, start_date=None, end_date=None):
    conn = get_db()

    try:
        query = """
            SELECT
                COALESCE(SUM(
                    CASE WHEN LOWER(kind) = 'income'
                    THEN amount ELSE 0 END
                ), 0) AS income,

                COALESCE(SUM(
                    CASE WHEN LOWER(kind) = 'expense'
                    THEN amount ELSE 0 END
                ), 0) AS expenses

            FROM lakshita_transactions
            WHERE user_id = ?
        """

        params = [user_id]

        if start_date and end_date:
            query += """
                AND transaction_date BETWEEN ? AND ?
            """
            params.extend([start_date, end_date])

        row = conn.execute(query, params).fetchone()

        return float(row["income"]), float(row["expenses"])

    finally:
        conn.close()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/index")
def index():
    return redirect(url_for("home"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get(
            "confirm_password", ""
        )

        if not username or not email or not password:
            flash("Please fill all required fields.", "error")

        elif len(password) < 6:
            flash("Password must contain at least 6 characters.", "error")

        elif password != confirm_password:
            flash("Passwords do not match.", "error")

        else:
            conn = get_db()

            try:
                conn.execute("""
                    INSERT INTO lakshita_users
                    (username, email, password_hash)
                    VALUES (?, ?, ?)
                """, (
                    username,
                    email,
                    generate_password_hash(password)
                ))

                conn.commit()
                flash("Account created successfully. Please login.", "success")
                return redirect(url_for("login"))

            except sqlite3.IntegrityError:
                flash("This email is already registered.", "error")

            finally:
                conn.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()

        try:
            user = conn.execute("""
                SELECT *
                FROM lakshita_users
                WHERE email = ? AND username = ?
            """, (email, username)).fetchone()

        finally:
            conn.close()

        if user and check_password_hash(
            user["password_hash"], password
        ):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid email, username or password.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have logged out.", "success")
    return redirect(url_for("login"))
@app.route("/dashboard")
@login_required
def dashboard():
    user_id = current_user_id()

    start, end, month_key = get_month_range(0)
    prev_start, prev_end, prev_key = get_month_range(-1)

    monthly_income, monthly_expenses = get_totals(
        user_id, start, end
    )

    _, previous_month_expenses = get_totals(
        user_id, prev_start, prev_end
    )

    conn = get_db()

    try:
        budget_row = conn.execute("""
            SELECT monthly_limit
            FROM lakshita_budgets
            WHERE user_id = ?
        """, (user_id,)).fetchone()

        monthly_budget = (
            float(budget_row["monthly_limit"])
            if budget_row else 0
        )

        transactions = conn.execute("""
            SELECT *
            FROM lakshita_transactions
            WHERE user_id = ?
            ORDER BY transaction_date DESC, id DESC
            LIMIT 10
        """, (user_id,)).fetchall()

        categories = conn.execute("""
            SELECT category, SUM(amount) AS total
            FROM lakshita_transactions
            WHERE user_id = ?
              AND LOWER(kind) = 'expense'
              AND transaction_date BETWEEN ? AND ?
            GROUP BY category
            ORDER BY total DESC
        """, (user_id, start, end)).fetchall()

        monthly_rows = conn.execute("""
            SELECT
                substr(transaction_date, 1, 7) AS month_key,
                SUM(CASE WHEN LOWER(kind) = 'income'
                    THEN amount ELSE 0 END) AS income,
                SUM(CASE WHEN LOWER(kind) = 'expense'
                    THEN amount ELSE 0 END) AS expenses
            FROM lakshita_transactions
            WHERE user_id = ?
            GROUP BY substr(transaction_date, 1, 7)
            ORDER BY month_key DESC
            LIMIT 6
        """, (user_id,)).fetchall()

    finally:
        conn.close()

    budget_percentage = (
        monthly_expenses / monthly_budget * 100
        if monthly_budget > 0 else 0
    )

    budget_alert_message = ""

    if monthly_budget > 0 and monthly_expenses > monthly_budget:
        budget_alert_message = "Your monthly budget has been exceeded."
    elif monthly_budget > 0 and budget_percentage >= 80:
        budget_alert_message = "Warning: You have used 80% of your budget."

    category_labels = [r["category"] for r in categories]
    category_values = [float(r["total"]) for r in categories]

    ordered_months = list(reversed(monthly_rows))

    monthly_labels = [r["month_key"] for r in ordered_months]
    monthly_income_data = [
        float(r["income"] or 0) for r in ordered_months
    ]
    monthly_expense_data = [
        float(r["expenses"] or 0) for r in ordered_months
    ]

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        monthly_income=monthly_income,
        monthly_expenses=monthly_expenses,
        balance=monthly_income - monthly_expenses,
        available_balance=monthly_income - monthly_expenses,
        monthly_budget=monthly_budget,
        budget_percentage=budget_percentage,
        budget_alert_message=budget_alert_message,
        current_month_expenses=monthly_expenses,
        previous_month_expenses=previous_month_expenses,
        transactions=transactions,
        recent_transactions=transactions,
        category_labels=category_labels,
        category_values=category_values,
        monthly_labels=monthly_labels,
        monthly_income_data=monthly_income_data,
        monthly_expense_data=monthly_expense_data,
        month=month_key,
        previous_month=prev_key
    )


@app.route("/expenses", methods=["GET", "POST"])
@login_required
def expenses():
    user_id = current_user_id()

    if request.method == "POST":
        kind = request.form.get("kind", "expense").strip().lower()
        description = request.form.get(
            "description", ""
        ).strip()
        category = request.form.get("category", "").strip()
        transaction_date = request.form.get(
            "transaction_date", date.today().isoformat()
        )

        try:
            amount = float(request.form.get("amount", "0"))
        except ValueError:
            amount = 0

        if kind not in ("income", "expense"):
            flash("Select a valid transaction type.", "error")

        elif amount <= 0:
            flash("Amount must be greater than zero.", "error")

        elif not category or not description:
            flash("Please enter description and category.", "error")

        else:
            conn = get_db()

            try:
                conn.execute("""
                    INSERT INTO lakshita_transactions
                    (user_id, kind, amount, category,
                     description, transaction_date)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    user_id, kind, amount, category,
                    description, transaction_date
                ))

                conn.commit()
                flash("Transaction added successfully.", "success")

            finally:
                conn.close()

        return redirect(url_for("expenses"))

    start, end, _ = get_month_range(0)
    total_income, total_expenses = get_totals(
        user_id, start, end
    )

    conn = get_db()

    try:
        transactions = conn.execute("""
            SELECT *
            FROM lakshita_transactions
            WHERE user_id = ?
            ORDER BY transaction_date DESC, id DESC
        """, (user_id,)).fetchall()

    finally:
        conn.close()

    return render_template(
        "expenses.html",
        username=session.get("username"),
        transactions=transactions,
        expenses=transactions,
        total_income=total_income,
        total_expenses=total_expenses,
        today=date.today().isoformat()
    )


@app.route("/edit-expense/<int:transaction_id>",
           methods=["GET", "POST"])
@login_required
def edit_expense(transaction_id):
    user_id = current_user_id()
    conn = get_db()

    try:
        transaction = conn.execute("""
            SELECT *
            FROM lakshita_transactions
            WHERE id = ? AND user_id = ?
        """, (transaction_id, user_id)).fetchone()

        if not transaction:
            flash("Transaction not found.", "error")
            return redirect(url_for("expenses"))

        if request.method == "POST":
            description = request.form.get(
                "description", ""
            ).strip()
            category = request.form.get("category", "").strip()
            kind = request.form.get("kind", "expense").lower()
            transaction_date = request.form.get(
                "transaction_date", date.today().isoformat()
            )

            try:
                amount = float(request.form.get("amount", "0"))
            except ValueError:
                amount = 0

            if kind not in ("income", "expense") or amount <= 0:
                flash("Enter valid transaction details.", "error")
            else:
                conn.execute("""
                    UPDATE lakshita_transactions
                    SET description = ?, category = ?,
                        kind = ?, amount = ?, transaction_date = ?
                    WHERE id = ? AND user_id = ?
                """, (
                    description, category, kind, amount,
                    transaction_date, transaction_id, user_id
                ))

                conn.commit()
                flash("Transaction updated.", "success")
                return redirect(url_for("expenses"))

    finally:
        conn.close()

    return render_template(
        "edit_expense.html",
        transaction=transaction,
        expense=transaction
    )


@app.route("/delete-expense/<int:transaction_id>",
           methods=["POST"])
@login_required
def delete_expense(transaction_id):
    conn = get_db()

    try:
        conn.execute("""
            DELETE FROM lakshita_transactions
            WHERE id = ? AND user_id = ?
        """, (transaction_id, current_user_id()))

        conn.commit()
        flash("Transaction deleted.", "success")

    finally:
        conn.close()

    return redirect(url_for("expenses"))
@app.route("/budget", methods=["GET", "POST"])
@login_required
def budget():
    user_id = current_user_id()

    conn = get_db()

    try:
        if request.method == "POST":
            raw_amount = (
                request.form.get("monthly_limit")
                or request.form.get("budget_amount")
                or request.form.get("amount")
                or "0"
            )

            try:
                amount = float(raw_amount)
            except ValueError:
                amount = -1

            if amount < 0:
                flash("Enter a valid monthly budget.", "error")
            else:
                conn.execute("""
                    INSERT INTO lakshita_budgets
                    (user_id, monthly_limit)
                    VALUES (?, ?)
                    ON CONFLICT(user_id)
                    DO UPDATE SET monthly_limit = excluded.monthly_limit
                """, (user_id, amount))

                conn.commit()
                flash("Monthly budget saved.", "success")

                return redirect(url_for("budget"))

        row = conn.execute("""
            SELECT monthly_limit
            FROM lakshita_budgets
            WHERE user_id = ?
        """, (user_id,)).fetchone()

    finally:
        conn.close()

    start, end, _ = get_month_range(0)
    _, monthly_expenses = get_totals(user_id, start, end)

    monthly_budget = (
        float(row["monthly_limit"]) if row else 0
    )

    remaining_amount = monthly_budget - monthly_expenses
    budget_percentage = (
        monthly_expenses / monthly_budget * 100
        if monthly_budget > 0 else 0
    )

    return render_template(
        "budget.html",
        monthly_budget=monthly_budget,
        monthly_limit=monthly_budget,
        monthly_expenses=monthly_expenses,
        remaining_amount=remaining_amount,
        budget_percentage=budget_percentage
    )
@app.route("/goals", methods=["GET", "POST"])
@login_required
def goals():
    user_id = current_user_id()

    if request.method == "POST":
        action = request.form.get("action", "")

        conn = get_db()

        try:
            if action == "create_goal":
                name = request.form.get(
                    "goal_name", ""
                ).strip()

                try:
                    target = float(
                        request.form.get("target_amount", "0")
                    )
                    months = int(
                        request.form.get("target_months", "6")
                    )
                except ValueError:
                    target, months = 0, 0

                if not name or target <= 0 or not (1 <= months <= 120):
                    flash("Enter valid goal details.", "error")
                else:
                    conn.execute("""
                        INSERT INTO lakshita_goals
                        (user_id, name, target, saved, target_months)
                        VALUES (?, ?, ?, 0, ?)
                    """, (user_id, name, target, months))

                    conn.commit()
                    flash("Savings goal created successfully.", "success")

            elif action == "add_saving":
                try:
                    goal_id = int(request.form.get("goal_id", "0"))
                    amount = float(request.form.get("amount", "0"))
                except ValueError:
                    goal_id, amount = 0, 0

                goal = conn.execute("""
                    SELECT *
                    FROM lakshita_goals
                    WHERE id = ? AND user_id = ?
                """, (goal_id, user_id)).fetchone()

                if not goal or amount <= 0:
                    flash("Enter a valid savings amount.", "error")
                else:
                    remaining = max(
                        float(goal["target"]) - float(goal["saved"]),
                        0
                    )

                    if amount > remaining:
                        flash(
                            "Savings amount cannot exceed the remaining target.",
                            "error"
                        )
                    else:
                        new_saved = float(goal["saved"]) + amount
                        month_key = date.today().strftime("%Y-%m")

                        conn.execute("""
                            UPDATE lakshita_goals
                            SET saved = ?
                            WHERE id = ? AND user_id = ?
                        """, (new_saved, goal_id, user_id))

                        existing = conn.execute("""
                            SELECT id
                            FROM lakshita_goal_monthly_savings
                            WHERE user_id = ?
                              AND goal_id = ?
                              AND month_key = ?
                        """, (user_id, goal_id, month_key)).fetchone()

                        if existing:
                            conn.execute("""
                                UPDATE lakshita_goal_monthly_savings
                                SET amount = amount + ?,
                                    updated_at = ?
                                WHERE id = ?
                            """, (
                                amount,
                                datetime.now().isoformat(timespec="seconds"),
                                existing["id"]
                            ))
                        else:
                            conn.execute("""
                                INSERT INTO lakshita_goal_monthly_savings
                                (user_id, goal_id, month_key, amount, updated_at)
                                VALUES (?, ?, ?, ?, ?)
                            """, (
                                user_id, goal_id, month_key, amount,
                                datetime.now().isoformat(timespec="seconds")
                            ))

                        conn.commit()
                        flash("Savings amount added successfully.", "success")

            elif action == "delete_goal":
                try:
                    goal_id = int(request.form.get("goal_id", "0"))
                except ValueError:
                    goal_id = 0

                conn.execute("""
                    DELETE FROM lakshita_goal_monthly_savings
                    WHERE goal_id = ? AND user_id = ?
                """, (goal_id, user_id))

                conn.execute("""
                    DELETE FROM lakshita_goals
                    WHERE id = ? AND user_id = ?
                """, (goal_id, user_id))

                conn.commit()
                flash("Savings goal deleted.", "success")

            else:
                flash("Unknown savings action.", "error")

        finally:
            conn.close()

        return redirect(url_for("goals"))

    conn = get_db()

    try:
        rows = conn.execute("""
            SELECT *
            FROM lakshita_goals
            WHERE user_id = ?
            ORDER BY id DESC
        """, (user_id,)).fetchall()

        history_rows = conn.execute("""
            SELECT
                s.goal_id,
                g.name AS goal_name,
                s.month_key,
                SUM(s.amount) AS saved
            FROM lakshita_goal_monthly_savings s
            JOIN lakshita_goals g ON g.id = s.goal_id
            WHERE s.user_id = ?
            GROUP BY s.goal_id, s.month_key
            ORDER BY s.month_key DESC, g.name
        """, (user_id,)).fetchall()

    finally:
        conn.close()

    goals_data = []

    for row in rows:
        target = float(row["target"])
        saved = float(row["saved"])
        months = max(int(row["target_months"] or 6), 1)

        progress = min(saved / target * 100, 100) if target > 0 else 0

        goals_data.append({
            "id": row["id"],
            "goal_name": row["name"],
            "target_amount": target,
            "saved_amount": saved,
            "remaining_amount": max(target - saved, 0),
            "base_monthly_target": target / months,
            "display_progress": progress
        })

        monthly_history = []

    for item in history_rows:
        month_key = item["month_key"]

        # Skip invalid records where month_key is NULL
        if not month_key:
            continue

        try:
            year, month = map(int, month_key.split("-"))
            last_day = calendar.monthrange(year, month)[1]
        except (ValueError, TypeError):
            continue

        month_start = f"{month_key}-01"
        month_end = f"{month_key}-{last_day:02d}"

        goal = next(
            (
                g for g in goals_data
                if g["id"] == item["goal_id"]
            ),
            None
        )

        monthly_target = (
            goal["base_monthly_target"]
            if goal else 0
        )

        saved_this_month = float(item["saved"] or 0)

        monthly_history.append({
            "goal_name": item["goal_name"],
            "month": month_key,
            "month_key": month_key,
            "saved": saved_this_month,
            "monthly_target": monthly_target,
            "completed": (
                saved_this_month >= monthly_target
                if monthly_target > 0 else False
            )
        })

        _, month_expenses = get_totals(
            user_id, month_start, month_end
        )

        # Monthly goal target from the current goal duration.
        goal = next(
            (g for g in goals_data if g["id"] == item["goal_id"]),
            None
        )

        monthly_target = (
            goal["base_monthly_target"] if goal else 0
        )

        monthly_history.append({
            "goal_name": item["goal_name"],
            "month": item["month_key"],
            "month_key": item["month_key"],
            "saved": float(item["saved"] or 0),
            "monthly_target": monthly_target,
            "completed": (
                float(item["saved"] or 0) >= monthly_target
                if monthly_target > 0 else False
            )
        })

    start, end, _ = get_month_range(0)
    income, expenses_total = get_totals(user_id, start, end)

    return render_template(
        "goals.html",
        username=session.get("username"),
        goals=goals_data,
        monthly_history=monthly_history,
        available_balance=income - expenses_total
    )
@app.route("/assistant")
@login_required
def assistant():
    return redirect(url_for("ai_assistant"))


@app.route("/ai-assistant")
@login_required
def ai_assistant():
    user_id = current_user_id()

    conn = get_db()

    try:
        category_rows = conn.execute("""
            SELECT category, SUM(amount) AS total
            FROM lakshita_transactions
            WHERE user_id = ?
              AND LOWER(kind) = 'expense'
            GROUP BY category
            ORDER BY total DESC
        """, (user_id,)).fetchall()

    finally:
        conn.close()

    category_totals = [
        (row["category"], float(row["total"]))
        for row in category_rows
    ]

    suggestions = []

    if category_totals:
        largest_category, largest_amount = category_totals[0]

        suggestions.append(
            f"Your highest recorded spending category is "
            f"{largest_category} (₹{largest_amount:.2f}). "
            "Review this category for possible savings."
        )
    else:
        suggestions.append(
            "Add a few transactions to receive spending suggestions."
        )

    start, end, _ = get_month_range(0)
    income, expenses_total = get_totals(user_id, start, end)

    if expenses_total > income:
        suggestions.append(
            "Your recorded expenses exceed this month's recorded income. "
            "Review non-essential spending."
        )
    else:
        suggestions.append(
            f"Your current month's recorded balance is "
            f"₹{income - expenses_total:.2f}."
        )

    return render_template(
        "finance.html",
        username=session.get("username"),
        category_totals=category_totals,
        suggestions=suggestions
    )


@app.route("/chat", methods=["GET", "POST"])
@login_required
def chat():
    user_id = current_user_id()
    user_message = ""
    reply = ""

    if request.method == "POST":
        user_message = request.form.get("message", "").strip()
        question = user_message.lower()

        start, end, _ = get_month_range(0)
        income, expenses_total = get_totals(user_id, start, end)

        conn = get_db()

        try:
            budget_row = conn.execute("""
                SELECT monthly_limit
                FROM lakshita_budgets
                WHERE user_id = ?
            """, (user_id,)).fetchone()

            budget_limit = (
                float(budget_row["monthly_limit"])
                if budget_row else 0
            )

            food_row = conn.execute("""
                SELECT COALESCE(SUM(amount), 0) AS total
                FROM lakshita_transactions
                WHERE user_id = ?
                  AND LOWER(kind) = 'expense'
                  AND LOWER(category) LIKE '%food%'
                  AND transaction_date BETWEEN ? AND ?
            """, (user_id, start, end)).fetchone()

        finally:
            conn.close()

        remaining_budget = budget_limit - expenses_total
        balance = income - expenses_total

        if not user_message:
            reply = "Please type a question."

        elif "food" in question:
            reply = (
                f"Your recorded food expenses this month are "
                f"₹{float(food_row['total']):.2f}."
            )

        elif "budget" in question:
            if budget_limit <= 0:
                reply = "You have not set a monthly budget yet."
            else:
                reply = (
                    f"Monthly budget: ₹{budget_limit:.2f}\n"
                    f"Expenses this month: ₹{expenses_total:.2f}\n"
                    f"Budget remaining: ₹{remaining_budget:.2f}"
                )

        elif "spend" in question or "expense" in question:
            reply = (
                f"Your recorded expenses this month are "
                f"₹{expenses_total:.2f}."
            )

        elif "income" in question or "balance" in question:
            reply = (
                f"Recorded income this month: ₹{income:.2f}\n"
                f"Recorded expenses: ₹{expenses_total:.2f}\n"
                f"Remaining balance: ₹{balance:.2f}"
            )

        elif "saving" in question or "save" in question:
            reply = (
                "Try reviewing non-essential expenses, setting a realistic "
                "monthly budget, and adding affordable deposits to your "
                "savings goals. Keep essential expenses a priority."
            )

        else:
            reply = (
                "I can answer questions about this month's spending, "
                "food expenses, recorded income, remaining budget, "
                "and ways to save money."
            )

    return render_template(
        "finance_chat.html",
        username=session.get("username"),
        user_message=user_message,
        reply=reply
    )


if __name__ == "__main__":
    app.run(debug=True)
