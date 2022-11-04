package spidsaml

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"text/template"
)

// AttributeConsumingService defines, well, an AttributeConsumingService.
type AttributeConsumingService struct {
	ServiceName string
	Attributes  []string
}

// SAMLBinding can be either HTTPRedirect or HTTPPost.
type SAMLBinding string

// Constants for SAMLBinding
const (
	HTTPRedirect SAMLBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	HTTPPost     SAMLBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

// SP represents our Service Provider
type SP struct {
	EntityID                   string
	KeyFile                    string
	CertFile                   string
	AssertionConsumerServices  []string
	SingleLogoutServices       map[string]SAMLBinding
	AttributeConsumingServices []AttributeConsumingService
	IDP                        map[string]*IDP
	Organization               Organization
	_cert                      *x509.Certificate
	_key                       *rsa.PrivateKey
}

// Session represents an active SPID session.
type Session struct {
	IDPEntityID  string
	NameID       string
	SessionIndex string
	AssertionXML []byte
	Level        int
	Attributes   map[string]string
}

// Organization defines SP Organization data
type Organization struct {
	Names        []string
	DisplayNames []string
	URLs         []string
}

// Cert returns the certificate of this Service Provider.
func (sp *SP) Cert() *x509.Certificate {
	if sp._cert == nil {
		// read file as a byte array
		byteValue, _ := ioutil.ReadFile(sp.CertFile)

		block, _ := pem.Decode(byteValue)
		if block == nil || block.Type != "CERTIFICATE" {
			panic("failed to parse certificate PEM")
		}

		var err error
		sp._cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic(err)
		}
	}
	return sp._cert
}

// Key returns the private key of this Service Provider
func (sp *SP) Key() *rsa.PrivateKey {
	if sp._key == nil {
		// read file as a byte array
		byteValue, _ := ioutil.ReadFile(sp.KeyFile)

		block, _ := pem.Decode(byteValue)
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			panic("failed to parse private key from PEM file")
		}

		var err error
		sp._key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			panic(err)
		}
	}
	return sp._key
}

// KeyPEM returns the private key of this Service Provider in PEM format
func (sp *SP) KeyPEM() []byte {
	key := sp.Key()
	var block = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return pem.EncodeToMemory(block)
}

// GetIDP returns an IDP object representing the Identity Provider matching the given entityID.
func (sp *SP) GetIDP(entityID string) (*IDP, error) {
	if value, ok := sp.IDP[entityID]; ok {
		return value, nil
	}
	return nil, errors.New("IdP not found")
}

// Metadata generates XML metadata of this Service Provider.
func (sp *SP) Metadata() string {
	return `<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:spid="https://spid.gov.it/saml-extensions" entityID="http://docker.for.mac.host.internal:8000" ID="pfx41ae242a-b440-2449-d77e-c0c3fa11e1af"><ds:Signature>
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
  <ds:Reference URI="#pfx41ae242a-b440-2449-d77e-c0c3fa11e1af"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>Q8LxkJUTTUbU9K7sGbN8Y54pwe4=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>HP+ph1QBkI8bBm5PV1r5fxo3xfEewJKgsBSZ9/0qTKbLUBLZCXqcEXOHWyDwOZP8uDgmFqzqMn3nsZqsNqC6Dbo7KUc8BbGThn3LNPIq5MJgFg4Qme/jI0zdpN6BD2ny3xqLoPb4//GenFaRAoMhLUO4FaWFADoY0wXnAFM37zJGZTDE22jp/HmvQRmdcRK5BsyuKjU+/fJyZZYg03inzSBKfVUmnTLbCVfCpRan9zuC7LithyLvXLMNij7rSguDT7LOeuoDmtoYHXI6Dt4B3OGCcEPBfSX8vAUGjjDcUF8c60rGvkxtTW+KH9B5UrtfsWFef3b3YM3xX1b3IjtLbg==</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICljCCAX4CCQDP2/0y0d0/dzANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJJVDAeFw0xODA2MjgwOTM2MDRaFw0xOTA2MjgwOTM2MDRaMA0xCzAJBgNVBAYTAklUMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo4i2HsG/+Qm3qe0gqwEOh4wlBYK181WCn3RTuyFNQh6mdn6pLdv/dYXY22zER2ufY227FFto3vqtSdT306lpIoVuXKBAVoWwcrzO0dadM4dyHX7KRmWSDT51GBqkP6Hj1UoUywbXp5q9GXP5uVL8U93caT11VZaalHhEjKxtSYJHDP7ZP/2k9p54JgVIonMF0DJVhx0smPZ3QdHX+my/JNevsnuXTZIyyu0KjcXlflKSldngVDjv9D6cGE4wGOa5Vz5M+z4tjKnJtfj/xacIWcj/4Ukuu6CDyQ8+YNCaE9YjitRmdi5ZqTDOoGKonmlbhCcfqPeRvGwfWXJcVR+qUwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBVO9pGMnJ3X5D6ny/32TM4fvFesdRBtSTnivkdssvn4o8u6570XZIpz2AFQ9eltREbobAqYuWrXIr+1x5aACsReFSjusSMNb9dUCwZbpcId53WQdGikXVkLwgRw9LfYSr73EfeUIIc9R5HCbR5p2piDzw9cNpR9wGhhL64g1zhy7O7bdWCXZ4cg9in9N2fCMTjdNpUvG4ZiToRdUqvuMDF4gsQJOwVwmN6BxQFloyODpdf1XoTk9dEqPqFO5B8h+DY/26JV8QYUPKzGUJkr24GxjFj5dlyd8++oQDBEz0WVC0uRl5nGj+MDAO0DmHNeaS05gWQpp/KpykPzKyQw7cg</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature> 

	<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
		<ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <ds:Reference URI="#_286e5a7cd5ae4ae8a3508a9e960d70e3834264fc71">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>7lIa9+CFBUU7u2gfKY2mwAsWPQELZOZBfY1UazhD/2I=</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
    </ds:Signature>
     
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true" WantAssertionsSigned="true"> 
        
        <md:KeyDescriptor use="signing"> 
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"> 
                <ds:X509Data> 
                    <ds:X509Certificate>MIICljCCAX4CCQDP2/0y0d0/dzANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJJVDAeFw0xODA2MjgwOTM2MDRaFw0xOTA2MjgwOTM2MDRaMA0xCzAJBgNVBAYTAklUMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo4i2HsG/+Qm3qe0gqwEOh4wlBYK181WCn3RTuyFNQh6mdn6pLdv/dYXY22zER2ufY227FFto3vqtSdT306lpIoVuXKBAVoWwcrzO0dadM4dyHX7KRmWSDT51GBqkP6Hj1UoUywbXp5q9GXP5uVL8U93caT11VZaalHhEjKxtSYJHDP7ZP/2k9p54JgVIonMF0DJVhx0smPZ3QdHX+my/JNevsnuXTZIyyu0KjcXlflKSldngVDjv9D6cGE4wGOa5Vz5M+z4tjKnJtfj/xacIWcj/4Ukuu6CDyQ8+YNCaE9YjitRmdi5ZqTDOoGKonmlbhCcfqPeRvGwfWXJcVR+qUwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBVO9pGMnJ3X5D6ny/32TM4fvFesdRBtSTnivkdssvn4o8u6570XZIpz2AFQ9eltREbobAqYuWrXIr+1x5aACsReFSjusSMNb9dUCwZbpcId53WQdGikXVkLwgRw9LfYSr73EfeUIIc9R5HCbR5p2piDzw9cNpR9wGhhL64g1zhy7O7bdWCXZ4cg9in9N2fCMTjdNpUvG4ZiToRdUqvuMDF4gsQJOwVwmN6BxQFloyODpdf1XoTk9dEqPqFO5B8h+DY/26JV8QYUPKzGUJkr24GxjFj5dlyd8++oQDBEz0WVC0uRl5nGj+MDAO0DmHNeaS05gWQpp/KpykPzKyQw7cg</ds:X509Certificate> 
                </ds:X509Data> 
            </ds:KeyInfo> 
        </md:KeyDescriptor>
        
        
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://docker.for.mac.host.internal:8000/spid-slo"/> 
        
        
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat> 

        
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://docker.for.mac.host.internal:8000/spid-sso" index="0" isDefault="true"/> 
        
        
        
        <md:AttributeConsumingService index="0"> 
            <md:ServiceName xml:lang="it">Service 1</md:ServiceName>
            
            <md:RequestedAttribute Name="fiscalNumber" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            
            <md:RequestedAttribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            
            <md:RequestedAttribute Name="familyName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            
            <md:RequestedAttribute Name="dateOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            
        </md:AttributeConsumingService>
        

    </md:SPSSODescriptor> 

	<md:Organization>
		
		<md:OrganizationName xml:lang="it">Foobar</md:OrganizationName>
		
		
		<md:OrganizationDisplayName xml:lang="it">Foobar</md:OrganizationDisplayName>
		
		
		<md:OrganizationURL xml:lang="it">http://docker.for.mac.host.internal:8000</md:OrganizationURL>
		
	</md:Organization>

	<md:ContactPerson contactType="other">
		<md:Extensions>
			<spid:IPACode>c_h501</spid:IPACode>
			<spid:Public/>
		</md:Extensions>
		<md:EmailAddress>tech-info@example.org</md:EmailAddress>
		<md:TelephoneNumber>+39 8472345634785</md:TelephoneNumber>
	</md:ContactPerson>

</md:EntityDescriptor>`

	const tmpl = `<?xml version="1.0"?> 
<md:EntityDescriptor 
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"  
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#" 
	xmlns:spid="https://spid.gov.it/saml-extensions"
    entityID="{{.EntityID}}"  
    ID="_681a637-6cd4-434f-92c3-4fed720b2ad8"> 

	<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
		<ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <ds:Reference URI="#_286e5a7cd5ae4ae8a3508a9e960d70e3834264fc71">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>7lIa9+CFBUU7u2gfKY2mwAsWPQELZOZBfY1UazhD/2I=</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
    </ds:Signature>
     
    <md:SPSSODescriptor  
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"  
        AuthnRequestsSigned="true"  
        WantAssertionsSigned="true"> 
        
        <md:KeyDescriptor use="signing"> 
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"> 
                <ds:X509Data> 
                    <ds:X509Certificate>{{ .Cert }}</ds:X509Certificate> 
                </ds:X509Data> 
            </ds:KeyInfo> 
        </md:KeyDescriptor>
        
        {{ range $url, $binding := .SingleLogoutServices }}
        <md:SingleLogoutService 
            Binding="{{ $binding }}"
            Location="{{ $url }}" /> 
        {{ end }}
        
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat> 

        {{ range $index, $url := .AssertionConsumerServices }}
        <md:AssertionConsumerService  
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"  
            Location="{{ $url }}"  
            index="{{ $index }}"  
            isDefault="{{ if gt $index 0 }}false{{ else }}true{{ end }}" /> 
        {{ end }}
        
        {{ range $index, $attcs := .AttributeConsumingServices }}
        <md:AttributeConsumingService index="{{ $index }}"> 
            <md:ServiceName xml:lang="it">{{ $attcs.ServiceName }}</md:ServiceName>
            {{ range $attr := $attcs.Attributes }}
            <md:RequestedAttribute Name="{{ $attr }}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/> 
            {{ end }}
        </md:AttributeConsumingService>
        {{ end }}

    </md:SPSSODescriptor> 

	<md:Organization>
		{{ range $name := .Organization.Names }}
		<md:OrganizationName xml:lang="it">{{ $name }}</md:OrganizationName>
		{{ end }}
		{{ range $displayName := .Organization.DisplayNames }}
		<md:OrganizationDisplayName xml:lang="it">{{ $displayName }}</md:OrganizationDisplayName>
		{{ end }}
		{{ range $url := .Organization.URLs }}
		<md:OrganizationURL xml:lang="it">{{ $url }}</md:OrganizationURL>
		{{ end }}
	</md:Organization>

	<md:ContactPerson contactType="other">
		<md:Extensions>
			<spid:IPACode>it1234</spid:IPACode>
			<spid:Public>true</spid:Public>
		</md:Extensions>
		<md:EmailAddress>tech-info@example.org</md:EmailAddress>
		<md:TelephoneNumber>+398472345634785</md:TelephoneNumber>
	</md:ContactPerson>

</md:EntityDescriptor>
`
	aux := struct {
		*SP
		Cert string
	}{
		sp,
		base64.StdEncoding.EncodeToString(sp.Cert().Raw),
	}

	t := template.Must(template.New("metadata").Parse(tmpl))
	var metadata bytes.Buffer
	t.Execute(&metadata, aux)

	return metadata.String()
}
