import base64


import flask


import database
import saml_handler


app = flask.Flask(__name__)


@app.get("/login")
def login_get():
    queries = flask.request.args
    saml_request = queries.get("SAMLRequest", None)

    if saml_request is None:
        return flask.jsonify(
            {"status": "error", "message": "'SAMLRequest' query was not found."}
        )
    return flask.render_template("login.html", saml_request=saml_request)


@app.post("/login")
def login_post():
    form = flask.request.form

    username = form.get("username", "")
    password = form.get("password", "")
    saml_request = form.get("saml_request", "")

    try:
        SAMLRequest = saml_handler.SAMLRequest(saml_request=saml_request)
    except:
        return flask.jsonify(
            {"status": "error", "message": "'SAMLRequest' is bad formated."}
        )
    user = database.get_user(
        database_path="database\\users.json", username=username, password=password
    )
    if None is user:
        return flask.jsonify(
            {"status": "error", "message": "invalid credentials provided"}
        )
    SAMLResponse = saml_handler.SAMLResponse(SAMLRequest, user["username"])
    SAMLResponse.set_field("email", user["email"])
    SAMLResponse.set_field("firstname", user["firstname"])
    SAMLResponse.set_field("lastname", user["lastname"])
    SAMLResponse.set_field("uid", user["username"])
    signed_assertion = SAMLResponse.sign("certs\\localhost.key", "certs\\localhost.crt")
    saml_assertion = base64.b64encode(signed_assertion.render().encode()).decode()
    return flask.render_template(
        "saml_response.html",
        saml_assertion=saml_assertion,
        assertion_consumer_service=SAMLRequest.assertion_consumer_service_url,
    )

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=443,
        debug=True,
        ssl_context=(
            "certs\\localhost.crt",
            "certs\\localhost.key",
        ),
    )
