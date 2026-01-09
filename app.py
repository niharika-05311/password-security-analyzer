print("APP STARTED")
from flask import Flask, render_template, request
import hashlib
import re

app = Flask(__name__)

# Load breached password hashes
def load_breached_passwords():
    try:
        with open("breached_passwords.txt", "r") as file:
            return set(line.strip() for line in file)
    except FileNotFoundError:
        return set()

breached_hashes = load_breached_passwords()

def check_strength(password):
    score = 0
    suggestions = []

    if len(password) >= 8:
        score += 1
    else:
        suggestions.append("Use at least 8 characters")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Add uppercase letters")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        suggestions.append("Add numbers")

    if re.search(r"[!@#$%^&*()_+]", password):
        score += 1
    else:
        suggestions.append("Add special characters")

    if score <= 1:
        strength = "Weak"
    elif score <= 3:
        strength = "Medium"
    else:
        strength = "Strong"

    return strength, suggestions

def check_breach(password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password in breached_hashes

@app.route("/", methods=["GET", "POST"])
def index():
    strength = None
    suggestions = []
    breached = False

    if request.method == "POST":
        password = request.form["password"]
        strength, suggestions = check_strength(password)
        breached = check_breach(password)

    return render_template(
        "index.html",
        strength=strength,
        suggestions=suggestions,
        breached=breached
    )

if __name__ == "__main__":
    app.run(debug=True)
