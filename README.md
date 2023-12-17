# SAML IdP

Python library to handle SAML requests and to respond with actual SAML responses.

# Example

```python
import saml_handler

SAMLRequest = saml_handler.SAMLRequest(saml_request="<SAML_Request_from_Service_Provider>")

# User authentication <...>
user = { ... }

SAMLResponse = saml_handler.SAMLResponse(saml_request=SAMLRequest, name_id=user["username"])
SAMLResponse.set_field("email", user["email"])
SAMLResponse.set_field("firstname", user["firstname"])
SAMLResponse.set_field("lastname", user["lastname"])
SAMLResponse.set_field("uid", user["username"])

signed_assertion = SAMLResponse.sign("certs/private.key", "certs/public.crt")

# Send assertion to the service provider <...>
```
