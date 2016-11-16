package uk.gov.ida.eidas.bridge.helpers;

import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.StatusResponseType;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;

public class EidasAuthnRequestGenerator {
    public static final String PROVIDER_NAME = "PROVIDER_NAME";
    private final String entityId;

    public EidasAuthnRequestGenerator(String entityId) {
        this.entityId = entityId;
    }

    private final OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();

    public AuthnRequest generateAuthnRequest(String authnReqeustId) {
        AuthnRequest eidasAuthnRequest = openSamlXmlObjectFactory.createAuthnRequest();
        eidasAuthnRequest.setID(authnReqeustId);
        eidasAuthnRequest.setConsent(StatusResponseType.UNSPECIFIED_CONSENT);
        eidasAuthnRequest.setForceAuthn(true);
        eidasAuthnRequest.setProviderName(PROVIDER_NAME);
        eidasAuthnRequest.setIssuer(openSamlXmlObjectFactory.createIssuer(entityId));

        return eidasAuthnRequest;
    }
}
