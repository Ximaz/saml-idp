require 'ruby-saml'


raw_response = File.read("test.xml")

def saml_settings
  settings = OneLogin::RubySaml::Settings.new

  settings.idp_cert_fingerprint = 5
  settings.assertion_consumer_service_url = "https://192.168.136.128/login/auth/saml/callback"
  settings.idp_cert_fingerprint = "d8396792508c33bf70559fcedeba9e2c05fd0400"
  settings
end

settings = saml_settings
response = OneLogin::RubySaml::Response.new(raw_response, {settings: settings})

response.attributes["fingerprint"] = 5
response.soft = false

puts response.is_valid?

puts "doc valid"

