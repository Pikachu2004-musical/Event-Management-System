## Event Management System 

This is a small **Flask + SQLite** web application that follows the uploaded flow/requirements:

- **Login** with hidden password input
- **Session** works properly (Flask session)
- **Role-based access**
  - Admin: Maintenance + Reports + Transactions
  - User: Reports + Transactions (no Maintenance)
- **Validations** on forms
- **Radio buttons**: only one can be selected
- **Checkbox**: checked = yes, unchecked = no
- **Vendor flow**: Main Page → Your Item / Add New Item / Transaction + related pages

### Default credentials

- **Admin**: `admin` / `admin`
- **User**: `user` / `user`

### Run (Windows PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
py .\app.py
```

Then open `http://127.0.0.1:5000`.

### Notes

- Database file is created at `data/app.db` automatically on first run (with seed data).


