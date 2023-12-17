import base64
import datetime
import ssl
import typing
import urllib.request
import urllib.parse
import uuid
import xml.etree.ElementTree as EET
import zlib

import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.asymmetric.padding
import cryptography.hazmat.primitives.serialization


def _bool(string: str | None) -> bool | None:
    if string == "true":
        return True
    if string == "false":
        return False


def find_children_by_name(parent: EET.Element, children_name: str) -> list[EET.Element]:
    return list(
        filter(
            lambda e: e.tag.endswith(children_name),
            parent.findall("./"),
        )
    )


def find_child_by_name(parent: EET.Element, child_name: str) -> EET.Element | None:
    children = find_children_by_name(parent, children_name=child_name)
    return children[0] if len(children) == 1 else None


class SAMLRequestNameIDPolicy:
    def __init__(
        self,
        allow_create: typing.Optional[bool] = None,
        fmt: typing.Optional[str] = None,
    ) -> None:
        self._allow_create = allow_create
        self._fmt = fmt

    @property
    def allow_create(self) -> bool | None:
        return self._allow_create

    @property
    def format(self) -> str | None:
        return self._fmt

    def __dict__(self):
        return {"allow_create": self.allow_create, "format": self.format}


class SAMLSPSSOAttributeConsumingServiceRequestedAttribute:
    def __init__(
        self,
        friendly_name: typing.Optional[str] = None,
        name: typing.Optional[str] = None,
        name_format: typing.Optional[str] = None,
        is_required: typing.Optional[bool] = None,
    ):
        self._friendly_name = friendly_name
        self._name = name
        self._name_format = name_format
        self._is_required = is_required

    @property
    def friendly_name(self) -> str | None:
        return self._friendly_name

    @property
    def name(self) -> str | None:
        return self._name

    @property
    def name_format(self) -> str | None:
        return self._name_format

    @property
    def is_required(self) -> bool | None:
        return self._is_required

    def __dict__(self):
        return {
            "friendly_name": self.friendly_name,
            "name": self.name,
            "name_format": self.name_format,
            "is_required": self.is_required,
        }


class SAMLACSFieldsSPSSODescriptorAssertionConsumerService:
    def __init__(self, assertion_consumer_service: EET.Element):
        self._assertion_consumer_service = assertion_consumer_service

    @property
    def binding(self) -> str | None:
        return self._assertion_consumer_service.attrib.get("Binding")

    @property
    def location(self) -> str | None:
        return self._assertion_consumer_service.attrib.get("Location")

    @property
    def index(self) -> int | None:
        monad = self._assertion_consumer_service.attrib.get("index")
        if monad is None:
            return None
        if not monad.isdecimal():
            return None
        return int(monad)

    @property
    def is_default(self) -> bool | None:
        return _bool(self._assertion_consumer_service.attrib.get("isDefault"))

    def __dict__(self):
        return {
            "binding": self.binding,
            "location": self.location,
            "index": self.index,
            "is_default": self.is_default,
        }


class SAMLACSFieldsSPSSODescriptorAttributeConsumingService:
    def __init__(self, attribute_consuming_service: EET.Element):
        self._attribute_consuming_service = attribute_consuming_service

    @property
    def index(self) -> int | None:
        monad = self._attribute_consuming_service.attrib.get("index")
        if monad is None:
            return None
        if not monad.isdecimal():
            return None
        return int(monad)

    @property
    def is_default(self) -> bool | None:
        return _bool(self._attribute_consuming_service.attrib.get("isDefault"))

    @property
    def service_name(self) -> str | None:
        service_name = find_child_by_name(
            self._attribute_consuming_service, "ServiceName"
        )
        return service_name.text if service_name is not None else None

    @property
    def requested_attributes(
        self,
    ) -> list[SAMLSPSSOAttributeConsumingServiceRequestedAttribute]:
        if None is self._attribute_consuming_service:
            return []
        return [
            SAMLSPSSOAttributeConsumingServiceRequestedAttribute(
                friendly_name=requested_attribute.attrib.get("FriendlyName"),
                name=requested_attribute.attrib.get("Name"),
                name_format=requested_attribute.attrib.get("NameFormat"),
                is_required=_bool(requested_attribute.attrib.get("isRequired")),
            )
            for requested_attribute in find_children_by_name(
                self._attribute_consuming_service,
                "RequestedAttribute",
            )
        ]

    def __dict__(self):
        return {
            "index": self.index,
            "is_default": self.is_default,
            "service_name": self.service_name,
            "requested_attributes": list(
                map(
                    lambda ra: ra.__dict__(),
                    self.requested_attributes,
                )
            ),
        }


class SAMLACSFieldsSPSSODescriptor:
    def __init__(self, sp_sso_descriptor: EET.Element | None):
        if sp_sso_descriptor is None:
            raise ValueError("SP SSO Descriptor was not found on metadata.")
        self._sp_sso_descriptor = sp_sso_descriptor

        name_id_format = find_child_by_name(self._sp_sso_descriptor, "NameIDFormat")
        if name_id_format is None:
            raise ValueError("Can't find NameID inside SP SSO Descriptor.")
        self._name_id_format = name_id_format

        assertion_consumer_service = find_child_by_name(
            self._sp_sso_descriptor, "AssertionConsumerService"
        )
        if assertion_consumer_service is None:
            raise ValueError(
                "Can't find Assertion Consumer Service inside SP SSO Descriptor."
            )
        self._assertion_consumer_service = (
            SAMLACSFieldsSPSSODescriptorAssertionConsumerService(
                assertion_consumer_service
            )
        )

        attribute_consuming_service = find_child_by_name(
            self._sp_sso_descriptor, "AttributeConsumingService"
        )
        if attribute_consuming_service is None:
            raise ValueError(
                "Can't find Attribute Consuming Service inside SP SSO Descriptor."
            )
        self._attribute_consuming_service = (
            SAMLACSFieldsSPSSODescriptorAttributeConsumingService(
                attribute_consuming_service
            )
        )

    @property
    def authn_requests_signed(self) -> bool | None:
        if None is self._sp_sso_descriptor:
            return None
        authn_requests_signed = self._sp_sso_descriptor.attrib.get(
            "AuthnRequestsSigned"
        )
        return _bool(authn_requests_signed)

    @property
    def want_assertions_signed(self) -> bool | None:
        if None is self._sp_sso_descriptor:
            return None
        want_assertions_signed = self._sp_sso_descriptor.attrib.get(
            "WantAssertionsSigned"
        )
        return _bool(want_assertions_signed)

    @property
    def protocol_support_enumeration(self) -> str | None:
        return self._sp_sso_descriptor.attrib.get("protocolSupportEnumeration")

    @property
    def name_id_format(self) -> str | None:
        return self._name_id_format.text

    @property
    def assertion_consumer_service(
        self,
    ) -> SAMLACSFieldsSPSSODescriptorAssertionConsumerService:
        return self._assertion_consumer_service

    @property
    def attribute_consuming_service(
        self,
    ) -> SAMLACSFieldsSPSSODescriptorAttributeConsumingService:
        return self._attribute_consuming_service

    def __dict__(self):
        return {
            "authn_requests_signed": self.authn_requests_signed,
            "want_assertions_signed": self.want_assertions_signed,
            "protocol_support_enumeration": self.protocol_support_enumeration,
            "name_id_format": self.name_id_format,
            "assertion_consumer_service": self.assertion_consumer_service.__dict__(),
            "attribute_consuming_service": self.attribute_consuming_service.__dict__(),
        }


class SAMLACSFields:
    def __init__(self, issuer: str) -> None:
        ssl_context = ssl._create_unverified_context()
        with urllib.request.urlopen(url=issuer, context=ssl_context) as response:
            metafields = response.read()

        self._saml_acs_fields = EET.fromstring(EET.canonicalize(metafields))

        self._sp_sso_descriptor = SAMLACSFieldsSPSSODescriptor(
            find_child_by_name(self._saml_acs_fields, "SPSSODescriptor")
        )

    @property
    def id(self) -> str | None:
        return self._saml_acs_fields.attrib.get("ID")

    @property
    def entity_id(self) -> str | None:
        return self._saml_acs_fields.attrib.get("entityID")

    @property
    def sp_sso_descriptor(self):
        return self._sp_sso_descriptor

    def __dict__(self):
        return {
            "id": self.id,
            "entity_id": self.entity_id,
            "sp_sso_descriptor": self.sp_sso_descriptor.__dict__(),
        }


class SAMLRequest:
    def __init__(self, saml_request: str):
        saml_request = urllib.parse.unquote(saml_request)
        b64_decoded_saml_request = base64.b64decode(
            saml_request.encode("unicode-escape")
        )
        # SAML Request doesn't have a 'header'. -15 padding to skip the verification.
        inflated_saml_request = zlib.decompress(b64_decoded_saml_request, -15).decode(
            "unicode-escape"
        )
        saml_request = EET.canonicalize(inflated_saml_request)
        self._saml_request = EET.fromstring(saml_request)

    @property
    def assertion_consumer_service_url(self) -> str | None:
        return self._saml_request.attrib.get("AssertionConsumerServiceURL")

    @property
    def assertion_consumer_service_fields(self) -> SAMLACSFields:
        if self.issuer is None:
            raise ValueError("Issuer can't be None.")
        saml_acs_fields = SAMLACSFields(self.issuer)
        if self.issuer != saml_acs_fields.entity_id:
            raise ValueError("Issuer isn't the Assertion Consumer Service.")
        return saml_acs_fields

    @property
    def destination(self) -> str | None:
        return self._saml_request.attrib.get("Destination")

    @property
    def issue_instant(self) -> datetime.datetime | None:
        date_str = self._saml_request.attrib.get("IssueInstant")
        if date_str is None:
            return None
        try:
            return datetime.datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
        except:
            return None

    @property
    def version(self) -> str | None:
        return self._saml_request.attrib.get("Version")

    @property
    def id(self) -> str | None:
        return self._saml_request.attrib.get("ID")

    @property
    def issuer(self) -> str | None:
        issuer = find_child_by_name(self._saml_request, "Issuer")
        return issuer.text if issuer is not None else None

    @property
    def name_id_policy(self) -> SAMLRequestNameIDPolicy | None:
        name_id_policy = find_child_by_name(self._saml_request, "NameIDPolicy")
        if name_id_policy is None:
            return None
        allow_create = name_id_policy.attrib.get("AllowCreate")
        allow_create = _bool(allow_create)
        fmt = name_id_policy.attrib.get("Format")
        return SAMLRequestNameIDPolicy(allow_create=allow_create, fmt=fmt)

    def __dict__(self):
        name_id_policy = self.name_id_policy
        return {
            "assertion_customer_service_url": self.assertion_consumer_service_url,
            "destination": self.destination,
            "id": self.id,
            "issue_instant": self.issue_instant,
            "version": self.version,
            "issuer": self.issuer,
            "name_id_policy": name_id_policy.__dict__()
            if name_id_policy is not None
            else None,
        }


class SAMLResponse:
    def __init__(self, saml_request: SAMLRequest, name_id: str):
        self._saml_request = saml_request
        self._saml_acs_fields = self._saml_request.assertion_consumer_service_fields
        self._fields = (
            self._saml_acs_fields.sp_sso_descriptor.attribute_consuming_service.requested_attributes
        )

        date_to_str = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")

        assertion_customer_service_url = (
            self._saml_request.assertion_consumer_service_url
        )
        destination = self._saml_request.destination
        request_id = self._saml_request.id

        idp_host = urllib.parse.urlparse(destination)
        issue_instant = self._saml_request.issue_instant
        issuer = self._saml_request.issuer

        # Creating the SAML Response XML structure
        self._saml_response = EET.Element(
            "samlp:Response",
            attrib={  # type: ignore
                "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
                "ID": f"_{uuid.uuid4()}",
                "Version": "2.0",
                "IssueInstant": date_to_str(datetime.datetime.utcnow()),
                "Destination": assertion_customer_service_url,
                "InResponseTo": request_id,
            },
        )

        # Adding the Issuer element
        issuer_element = EET.SubElement(
            self._saml_response,
            "saml:Issuer",
            attrib={"xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion"},
        )

        issuer_element.text = f"{idp_host.scheme}://{idp_host.netloc}"

        status_element = EET.SubElement(self._saml_response, "samlp:Status")
        status_code_element = EET.SubElement(
            status_element,
            "samlp:StatusCode",
            attrib={"Value": "urn:oasis:names:tc:SAML:2.0:status:Success"},
        )

        self._assertion = EET.SubElement(
            self._saml_response,
            "saml:Assertion",
            attrib={
                "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
                "ID": f"_{uuid.uuid4()}",
                "IssueInstant": date_to_str(datetime.datetime.utcnow()),
                "Version": "2.0",
            },
        )

        assertion_issuer_element = EET.SubElement(
            self._assertion,
            "saml:Issuer",
            attrib={"xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion"},
        )

        assertion_issuer_element.text = f"{idp_host.scheme}://{idp_host.netloc}"

        # Adding the subject element
        subject_element = EET.SubElement(
            self._assertion,
            "saml:Subject",
        )
        subject_name_id_element = EET.SubElement(
            subject_element,
            "saml:NameID",
            attrib={  # type: ignore
                "SPNameQualifier": self._saml_request.issuer,
                "Format": self._saml_request.name_id_policy.format,  # type: ignore
            },
        )
        subject_name_id_element.text = name_id
        subject_confirmation_element = EET.SubElement(
            subject_element,
            "saml:SubjectConfirmation",
            attrib={"Method": "urn:oasis:names:tc:SAML:2.0:cm:bearer"},
        )
        subject_confirmation_data_element = EET.SubElement(
            subject_confirmation_element,
            "saml:SubjectConfirmationData",
            attrib={  # type: ignore
                "NotBefore": date_to_str(
                    datetime.datetime.fromtimestamp(
                        datetime.datetime.utcnow().timestamp() - 10
                    )
                ),
                "NotOnOrAfter": date_to_str(
                    datetime.datetime.fromtimestamp(
                        datetime.datetime.utcnow().timestamp() + 60 * 60 * 24 * 365
                    )
                ),
                "Recipient": self._saml_request.assertion_consumer_service_url,
                "InResponseTo": request_id,
            },
        )

        assertion_condition_element = EET.SubElement(
            self._assertion,
            "saml:Conditions",
            attrib={
                "NotBefore": date_to_str(datetime.datetime.utcnow()),
                "NotOnOrAfter": date_to_str(
                    datetime.datetime.fromtimestamp(
                        datetime.datetime.utcnow().timestamp() + (60 * 10)
                    )
                ),
            },
        )

        assertion_condition_audience_restriction_element = EET.SubElement(
            assertion_condition_element,
            "saml:AudienceRestriction",
        )

        assertion_condition_audience_element = EET.SubElement(
            assertion_condition_audience_restriction_element,
            "saml:Audience",
        )

        assertion_condition_audience_element.text = self._saml_request.issuer

        authnstatement_element = EET.SubElement(
            self._assertion,
            "saml:AuthnStatement",
            attrib={
                "AuthnInstant": date_to_str(
                    datetime.datetime.fromtimestamp(
                        datetime.datetime.utcnow().timestamp()
                    )
                ),
                "SessionNotOnOrAfter": date_to_str(
                    datetime.datetime.fromtimestamp(
                        datetime.datetime.utcnow().timestamp() + 60 * 60 * 24 * 365
                    )
                ),
                "SessionIndex": f"_{uuid.uuid4()}",
            },
        )

        authncontext_element = EET.SubElement(
            authnstatement_element,
            "saml:AuthnContext",
        )

        authncontextclassref_element = EET.SubElement(
            authncontext_element,
            "saml:AuthnContextClassRef",
        )

        authncontextclassref_element.text = (
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
        )

        self._attributes = EET.SubElement(
            self._assertion,
            "saml:AttributeStatement",
            attrib={"xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion"},
        )

    def set_field(self, name: str, value: str):
        field = list(filter(lambda f: f.name == name, self._fields))
        if len(field) != 1:
            raise ValueError(
                f"The field '{name}' is not supported by the service provider."
            )
        field = field[0]
        attribute = EET.SubElement(
            self._attributes,
            "saml:Attribute",
            attrib={
                "Name": f"urn:oasis:names:tc:SAML:attribute:{name}",
                "NameFormat": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            },
        )
        attribute_value_element = EET.SubElement(
            attribute,
            "saml:AttributeValue",
        )
        attribute_value_element.text = str(value)

    def sign(self, private_key_path: str, public_key_path: str):
        signature_element = EET.Element(
            "ds:Signature",
            attrib={"xmlns:ds": "http://www.w3.org/2000/09/xmldsig#"},
        )

        signed_info_element = EET.SubElement(
            signature_element,
            "ds:SignedInfo",
            attrib={"xmlns:ds": "http://www.w3.org/2000/09/xmldsig#"},
        )
        canonicalization_method = EET.SubElement(
            signed_info_element,
            "ds:CanonicalizationMethod",
            attrib={"Algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#"},
        )
        signature_method = EET.SubElement(
            signed_info_element,
            "ds:SignatureMethod",
            attrib={"Algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"},
        )
        reference = EET.SubElement(
            signed_info_element,
            "ds:Reference",
            attrib={"URI": f"#{self._assertion.attrib.get('ID')}"},
        )
        transforms = EET.SubElement(reference, "ds:Transforms")
        transform_1 = EET.SubElement(
            transforms,
            "ds:Transform",
            attrib={
                "Algorithm": "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
            },
        )
        transform_2 = EET.SubElement(
            transforms,
            "ds:Transform",
            attrib={"Algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#"},
        )
        digest_method = EET.SubElement(
            reference,
            "ds:DigestMethod",
            attrib={"Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"},
        )

        with open(private_key_path, "rb") as key_file:
            private_key_data = key_file.read()
        with open(public_key_path, "rb") as key_file:
            public_key_data = key_file.read()
        private_key = cryptography.hazmat.primitives.serialization.load_pem_private_key(
            private_key_data, password=None
        )
        public_key_data = public_key_data[
            len("-----BEGIN CERTIFICATE-----") : -len("-----END CERTIFICATE-----") - 1
        ].decode()

        sha256_hash = cryptography.hazmat.primitives.hashes.Hash(
            cryptography.hazmat.primitives.hashes.SHA256()
        )
        assertion_str = EET.tostring(self._assertion).decode("unicode-escape")
        canonicalized_assertion = EET.canonicalize(assertion_str)

        sha256_hash.update(canonicalized_assertion.encode())
        digest_value = sha256_hash.finalize()
        digest_b64 = base64.b64encode(digest_value).decode("utf-8")

        digest_value_element = EET.SubElement(reference, "ds:DigestValue")
        digest_value_element.text = digest_b64

        signed_info_str = EET.tostring(signed_info_element)
        signed_info_str = EET.canonicalize(signed_info_str)

        signature = private_key.sign(  # type: ignore
            signed_info_str.encode(),
            cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),  # type: ignore
            cryptography.hazmat.primitives.hashes.SHA256(),  # type: ignore
        )
        signature_b64 = base64.b64encode(signature).decode().replace("\n", "")
        signature_value = EET.SubElement(signature_element, "ds:SignatureValue")
        signature_value.text = signature_b64

        signed_info_element = EET.SubElement(signature_element, "ds:KeyInfo")
        x509_data = EET.SubElement(signed_info_element, "ds:X509Data")
        x509_certificate = EET.SubElement(x509_data, "ds:X509Certificate")
        x509_certificate.text = public_key_data

        self._assertion.insert(1, signature_element)
        return self

    def render(self) -> str:
        xml_string = EET.tostring(self._saml_response, encoding="unicode")
        return xml_string
