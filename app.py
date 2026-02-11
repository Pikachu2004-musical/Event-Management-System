from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Optional

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "app.db"


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")

    (BASE_DIR / "data").mkdir(exist_ok=True)
    init_db()

    @app.before_request
    def load_logged_in_user() -> None:
        user_id = session.get("user_id")
        if user_id is None:
            g.user = None
        else:
            g.user = query_one("SELECT id, username, role FROM users WHERE id = ?", (user_id,))

    def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view)
        def wrapped_view(**kwargs: Any) -> Any:
            if g.user is None:
                return redirect(url_for("login"))
            return view(**kwargs)

        return wrapped_view

    def role_required(*roles: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
            @wraps(view)
            def wrapped_view(**kwargs: Any) -> Any:
                if g.user is None:
                    return redirect(url_for("login"))
                if g.user["role"] not in roles:
                    abort(403)
                return view(**kwargs)

            return wrapped_view

        return decorator

    @app.get("/")
    def index() -> Any:
        if g.user:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Any:
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""

            error = None
            if not username:
                error = "User Id is required."
            elif not password:
                error = "Password is required."
            else:
                user = query_one("SELECT * FROM users WHERE username = ?", (username,))
                if user is None or not check_password_hash(user["password_hash"], password):
                    error = "Invalid credentials."

            if error:
                flash(error, "error")
            else:
                session.clear()
                session["user_id"] = user["id"]
                flash(f"Welcome, {user['username']}!", "success")
                return redirect(url_for("dashboard"))

        return render_template("login.html")

    @app.post("/logout")
    def logout() -> Any:
        session.clear()
        flash("Logged out.", "success")
        return redirect(url_for("login"))

    @app.get("/dashboard")
    @login_required
    def dashboard() -> Any:
        # Flow chart link exists on all pages (per requirement); shown in base layout.
        return render_template("dashboard.html")

    # ---------------------------
    # Vendor module (available to admin + user)
    # ---------------------------
    @app.get("/vendor")
    @role_required("admin", "user")
    def vendor_main() -> Any:
        return render_template("vendor/main.html")

    @app.get("/vendor/items")
    @role_required("admin", "user")
    def vendor_items() -> Any:
        items = query_all(
            "SELECT id, name, status, created_at FROM items ORDER BY created_at DESC, id DESC"
        )
        return render_template("vendor/items.html", items=items)

    @app.route("/vendor/items/new", methods=["GET", "POST"])
    @role_required("admin", "user")
    def vendor_item_new() -> Any:
        if request.method == "POST":
            name = (request.form.get("name") or "").strip()
            status = (request.form.get("status") or "").strip()
            is_active = 1 if request.form.get("is_active") == "on" else 0  # checkbox yes/no

            error = None
            if not name:
                error = "Item name is required."
            elif status not in {"available", "unavailable", "pending"}:
                error = "Select a valid status."

            if error:
                flash(error, "error")
            else:
                execute(
                    "INSERT INTO items (name, status, is_active) VALUES (?, ?, ?)",
                    (name, status, is_active),
                )
                flash("Item added.", "success")
                return redirect(url_for("vendor_items"))

        return render_template("vendor/item_new.html")

    @app.post("/vendor/items/<int:item_id>/delete")
    @role_required("admin", "user")
    def vendor_item_delete(item_id: int) -> Any:
        execute("DELETE FROM items WHERE id = ?", (item_id,))
        flash("Item deleted.", "success")
        return redirect(url_for("vendor_items"))

    @app.get("/vendor/product-status")
    @role_required("admin", "user")
    def vendor_product_status() -> Any:
        # Product Status is a simple filtered view.
        status = (request.args.get("status") or "").strip()
        params: tuple[Any, ...] = ()
        where = ""
        if status in {"available", "unavailable", "pending"}:
            where = "WHERE status = ?"
            params = (status,)
        items = query_all(
            f"SELECT id, name, status, is_active, created_at FROM items {where} ORDER BY created_at DESC",
            params,
        )
        return render_template("vendor/product_status.html", items=items, status=status)

    @app.route("/vendor/request-item", methods=["GET", "POST"])
    @role_required("admin", "user")
    def vendor_request_item() -> Any:
        items = query_all("SELECT id, name, status FROM items ORDER BY name ASC")
        if request.method == "POST":
            item_id = request.form.get("item_id")
            quantity_raw = (request.form.get("quantity") or "").strip()
            urgency = request.form.get("urgency")  # radio: one option
            notes = (request.form.get("notes") or "").strip()

            error = None
            try:
                quantity = int(quantity_raw)
            except ValueError:
                quantity = 0

            if not item_id:
                error = "Select an item."
            elif quantity <= 0:
                error = "Quantity must be a positive number."
            elif urgency not in {"low", "medium", "high"}:
                error = "Select urgency."

            if error:
                flash(error, "error")
            else:
                execute(
                    """
                    INSERT INTO requests (requested_by_user_id, item_id, quantity, urgency, notes)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (g.user["id"], int(item_id), quantity, urgency, notes),
                )
                flash("Request submitted.", "success")
                return redirect(url_for("vendor_user_requests"))

        return render_template("vendor/request_item.html", items=items)

    @app.get("/vendor/view-product")
    @role_required("admin", "user")
    def vendor_view_product() -> Any:
        items = query_all(
            "SELECT id, name, status, is_active, created_at FROM items ORDER BY created_at DESC"
        )
        return render_template("vendor/view_product.html", items=items)

    # ---------------------------
    # Transactions / Requests
    # ---------------------------
    @app.get("/transactions")
    @role_required("admin", "user")
    def transactions() -> Any:
        txns = query_all(
            """
            SELECT r.id, r.quantity, r.urgency, r.status, r.created_at,
                   u.username AS requested_by, i.name AS item_name
            FROM requests r
            JOIN users u ON u.id = r.requested_by_user_id
            JOIN items i ON i.id = r.item_id
            ORDER BY r.created_at DESC, r.id DESC
            """
        )
        return render_template("transactions/index.html", txns=txns)

    @app.get("/transactions/user-requests")
    @role_required("admin", "user")
    def vendor_user_requests() -> Any:
        rows = query_all(
            """
            SELECT r.id, r.quantity, r.urgency, r.status, r.created_at, i.name AS item_name
            FROM requests r
            JOIN items i ON i.id = r.item_id
            WHERE r.requested_by_user_id = ?
            ORDER BY r.created_at DESC, r.id DESC
            """,
            (g.user["id"],),
        )
        return render_template("transactions/user_requests.html", rows=rows)

    @app.post("/transactions/<int:req_id>/set-status")
    @role_required("admin")
    def txn_set_status(req_id: int) -> Any:
        status = request.form.get("status")
        if status not in {"approved", "rejected", "pending"}:
            flash("Invalid status.", "error")
            return redirect(url_for("transactions"))
        execute("UPDATE requests SET status = ? WHERE id = ?", (status, req_id))
        flash("Status updated.", "success")
        return redirect(url_for("transactions"))

    # ---------------------------
    # Reports (available to admin + user)
    # ---------------------------
    @app.get("/reports")
    @role_required("admin", "user")
    def reports() -> Any:
        # Simple reports: counts by status, recent requests, items count.
        item_counts = query_all(
            "SELECT status, COUNT(*) AS count FROM items GROUP BY status ORDER BY status"
        )
        req_counts = query_all(
            "SELECT status, COUNT(*) AS count FROM requests GROUP BY status ORDER BY status"
        )
        recent_requests = query_all(
            """
            SELECT r.id, r.quantity, r.urgency, r.status, r.created_at,
                   u.username AS requested_by, i.name AS item_name
            FROM requests r
            JOIN users u ON u.id = r.requested_by_user_id
            JOIN items i ON i.id = r.item_id
            ORDER BY r.created_at DESC, r.id DESC
            LIMIT 10
            """
        )
        return render_template(
            "reports/index.html",
            item_counts=item_counts,
            req_counts=req_counts,
            recent_requests=recent_requests,
        )

    # ---------------------------
    # Maintenance (admin only) - mandatory
    # ---------------------------
    @app.get("/maintenance")
    @role_required("admin")
    def maintenance() -> Any:
        users = query_all("SELECT id, username, role, created_at FROM users ORDER BY id ASC")
        return render_template("maintenance/index.html", users=users)

    @app.route("/maintenance/users/new", methods=["GET", "POST"])
    @role_required("admin")
    def maintenance_user_new() -> Any:
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            role = (request.form.get("role") or "").strip()
            password = request.form.get("password") or ""

            error = None
            if not username:
                error = "Username is required."
            elif role not in {"admin", "user"}:
                error = "Select a valid role."
            elif len(password) < 4:
                error = "Password must be at least 4 characters."
            elif query_one("SELECT id FROM users WHERE username = ?", (username,)) is not None:
                error = "Username already exists."

            if error:
                flash(error, "error")
            else:
                execute(
                    "INSERT INTO users (username, role, password_hash) VALUES (?, ?, ?)",
                    (username, role, generate_password_hash(password)),
                )
                flash("User created.", "success")
                return redirect(url_for("maintenance"))

        return render_template("maintenance/user_new.html")

    # ---------------------------
    # Membership (from instructions screenshot)
    # ---------------------------
    @app.route("/membership/add", methods=["GET", "POST"])
    @role_required("admin", "user")
    def membership_add() -> Any:
        if request.method == "POST":
            member_name = (request.form.get("member_name") or "").strip()
            plan = request.form.get("plan")  # radio, one only. default handled by template
            error = None
            if not member_name:
                error = "Member name is required."
            elif plan not in {"6m", "1y", "2y"}:
                error = "Select a membership plan."

            if error:
                flash(error, "error")
            else:
                execute(
                    "INSERT INTO memberships (member_name, plan_code, status) VALUES (?, ?, 'active')",
                    (member_name, plan),
                )
                flash("Membership added.", "success")
                return redirect(url_for("membership_update"))

        return render_template("membership/add.html")

    @app.route("/membership/update", methods=["GET", "POST"])
    @role_required("admin", "user")
    def membership_update() -> Any:
        memberships = query_all(
            "SELECT id, member_name, plan_code, status, created_at FROM memberships ORDER BY created_at DESC, id DESC"
        )
        selected_id = request.args.get("id")
        selected = None
        if selected_id:
            try:
                selected = query_one("SELECT * FROM memberships WHERE id = ?", (int(selected_id),))
            except ValueError:
                selected = None

        if request.method == "POST":
            membership_id = request.form.get("membership_id")
            action = request.form.get("action")  # extend/cancel
            extend_plan = request.form.get("extend_plan")  # radio, default in template

            error = None
            if not membership_id:
                error = "Membership Number is required."
            else:
                try:
                    membership_id_int = int(membership_id)
                except ValueError:
                    membership_id_int = 0
                membership = query_one("SELECT * FROM memberships WHERE id = ?", (membership_id_int,))
                if membership is None:
                    error = "Membership not found."

            if not error:
                if action not in {"extend", "cancel"}:
                    error = "Select an action."

            if not error and action == "extend":
                if extend_plan not in {"6m", "1y", "2y"}:
                    error = "Select an extension plan."

            if error:
                flash(error, "error")
            else:
                if action == "cancel":
                    execute("UPDATE memberships SET status = 'cancelled' WHERE id = ?", (membership_id_int,))
                    flash("Membership cancelled.", "success")
                else:
                    execute("UPDATE memberships SET plan_code = ? WHERE id = ?", (extend_plan, membership_id_int))
                    flash("Membership extended/updated.", "success")
                return redirect(url_for("membership_update", id=membership_id_int))

        # If membership number selected, rest of fields are populated (template reads `selected`).
        return render_template(
            "membership/update.html",
            memberships=memberships,
            selected=selected,
        )

    # ---------------------------
    # Flow chart page (help navigate)
    # ---------------------------
    @app.get("/flow-chart")
    def flow_chart() -> Any:
        return render_template("flow_chart.html")

    return app


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        g.db = con
    return g.db


def query_one(sql: str, params: tuple[Any, ...] = ()) -> Optional[sqlite3.Row]:
    con = get_db()
    cur = con.execute(sql, params)
    row = cur.fetchone()
    cur.close()
    return row


def query_all(sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    con = get_db()
    cur = con.execute(sql, params)
    rows = cur.fetchall()
    cur.close()
    return rows


def execute(sql: str, params: tuple[Any, ...] = ()) -> None:
    con = get_db()
    con.execute(sql, params)
    con.commit()


def init_db() -> None:
    DB_PATH.parent.mkdir(exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    try:
        con.executescript(
            """
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('available','unavailable','pending')),
                is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                requested_by_user_id INTEGER NOT NULL,
                item_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                urgency TEXT NOT NULL CHECK(urgency IN ('low','medium','high')),
                notes TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (requested_by_user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS memberships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                member_name TEXT NOT NULL,
                plan_code TEXT NOT NULL CHECK(plan_code IN ('6m','1y','2y')),
                status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','cancelled')),
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            """
        )

        # Seed default users (idempotent)
        cur = con.execute("SELECT COUNT(*) AS c FROM users")
        count = cur.fetchone()[0]
        if count == 0:
            con.execute(
                "INSERT INTO users (username, role, password_hash) VALUES (?, ?, ?)",
                ("admin", "admin", generate_password_hash("admin")),
            )
            con.execute(
                "INSERT INTO users (username, role, password_hash) VALUES (?, ?, ?)",
                ("user", "user", generate_password_hash("user")),
            )
            con.execute(
                "INSERT INTO items (name, status, is_active) VALUES (?, ?, ?)",
                ("Sample Item A", "available", 1),
            )
            con.execute(
                "INSERT INTO items (name, status, is_active) VALUES (?, ?, ?)",
                ("Sample Item B", "pending", 1),
            )
            con.commit()
    finally:
        con.close()


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=True)


