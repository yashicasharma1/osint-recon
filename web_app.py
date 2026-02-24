from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
    with open("test.html") as f:
        return f.read()

if __name__ == "__main__":
    app.run(debug=True)
def run_recon(domain):
    data = {}
    try:
        data["ip"] = socket.gethostbyname(domain)
    except:
        data["ip"] = "Unable to resolve"
    return data


@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        domain = request.form.get("domain")
        result = run_recon(domain)

    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)