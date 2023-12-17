# SAML IdP

Python library to handle SAML requests and to respond with actual SAML responses.

# Example

Python code which handles an SAML Request sent by a Service Provider :

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

The XML SAML Response produced by the `saml_handler` :

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="[IDENTITY_PROVIDER_RESPONSE_ID]" Version="2.0" IssueInstant="2023-12-17T22:53:41Z"
    Destination="[SERVICE_PROVIDER_ACS]" InResponseTo="[SERVICE_PROVIDER_REQUEST_ID]">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        [IDENTITY_PROVIDER]
    </saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </samlp:Status>
    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="[IDENTITY_PROVIDER_ASSERTION_ID]"
        IssueInstant="2023-12-17T22:53:41Z" Version="2.0">
        <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            [IDENTITY_PROVIDER]
        </saml:Issuer>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
                <ds:Reference URI="#[IDENTITY_PROVIDER_ASSERTION_ID]">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
                    <ds:DigestValue>
                        [SHA-256]
                    </ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>[ASSERTION_SIGNATURE]</ds:SignatureValue>
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>[PUBLIC_KEY]</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </ds:Signature>
        <saml:Subject>
            <saml:NameID SPNameQualifier="[SERVICE_PROVIDER_METADATA_URL]"
                Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">
                [NAME_ID_VALUE]
            </saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData NotBefore="2023-12-17T22:53:31Z" NotOnOrAfter="2024-12-16T22:53:41Z"
                    Recipient="[SERVICE_PROVIDER_ACS]" InResponseTo="[SERVICE_PROVIDER_REQUEST_ID]" />
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="2023-12-17T22:53:41Z" NotOnOrAfter="2023-12-17T23:03:41Z">
            <saml:AudienceRestriction>
                <saml:Audience>
                    [SERVICE_PROVIDER_METADATA_URL]
                </saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="2023-12-17T22:53:41Z" SessionNotOnOrAfter="2024-12-16T22:53:41Z"
            SessionIndex="_ccca26b6-b67b-4bed-9bfa-0ff01f48ce0f">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>
                    urn:oasis:names:tc:SAML:2.0:ac:classes:Password
                </saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:Attribute Name="urn:oasis:names:tc:SAML:attribute:..."
                NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                <saml:AttributeValue>
                    ...
                </saml:AttributeValue>
            </saml:Attribute>
            ...
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>
```