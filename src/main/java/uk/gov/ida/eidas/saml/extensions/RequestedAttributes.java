package uk.gov.ida.eidas.saml.extensions;

import org.opensaml.saml.common.SAMLObject;

import javax.xml.namespace.QName;

public interface RequestedAttributes extends SAMLObject {
    String EIDAS_EXTENSIONS_NAMESPACE = "http://eidas.europa.eu/saml-extensions";

    String DEFAULT_ELEMENT_LOCAL_NAME = "ReqeustedAttributes";
}
