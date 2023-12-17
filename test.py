import pathlib


import saml_handler

saml_request = "jZFLS8NAEMe%2FSm57ymtTbbMkgdAiFKpIqx68yJhMbHCzG3cmPr69SYtYL8Xr8Ps%2FZiYj6HSvyoH3ZotvAxJ7JRE6bq1ZWkNDh26H7r2t8H67ycWeuScVhvFcBjIK4iiQobYvrQlh9Agnu7ACrZ%2BhehXeavRrDUxmv1JtR2BviY9C4a1XuXhKG0yiOgV%2FDtj4swYufVjEtV9B3MwSmeAiTUeUaMC1IQbDuZCRTPxY%2BvH8TkqVxOoieRTeAzo6BMogEt5npw2pqVcuBmeUBWpJGeiQFFdqV15v1Agq%2BNn6VNKf1%2FTOsq2sFkU20erQzhX%2FuVGHDDUwZOGpMju%2B42ZMWq9urW6rL6%2FU2n4sHQJjLtgNKLwr6zrg892mSVv7zQFV%2FXQTYjQswuKY%2BffrxTc%3D"
user = {
    "username": "malo",
    "password": "malo",
    "email": "malo.durand@epitech.eu",
    "firstname": "DURAND",
    "lastname": "Malo",
}

SAMLRequest = saml_handler.SAMLRequest(saml_request=saml_request)

SAMLResponse = saml_handler.SAMLResponse(SAMLRequest, user["username"])
SAMLResponse.set_field("email", user["email"])
SAMLResponse.set_field("firstname", user["firstname"])
SAMLResponse.set_field("lastname", user["lastname"])
SAMLResponse.set_field("uid", user["username"])

signed_assertion = SAMLResponse.sign("certs/private.key", "certs/public.crt")

pathlib.Path("saml_assertion.xml").write_text(signed_assertion.render())
