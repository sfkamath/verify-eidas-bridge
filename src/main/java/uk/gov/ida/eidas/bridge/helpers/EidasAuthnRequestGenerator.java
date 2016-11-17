package uk.gov.ida.eidas.bridge.helpers;

import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.saml2.core.impl.ExtensionsBuilder;
import uk.gov.ida.eidas.common.LevelOfAssurance;
import uk.gov.ida.eidas.saml.extensions.SPType;
import uk.gov.ida.eidas.saml.extensions.SPTypeImpl;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;

public class EidasAuthnRequestGenerator {
    public static final String PROVIDER_NAME = "PROVIDER_NAME";
    private final OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();
    private final XMLObjectBuilderFactory xmlObjectBuilderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
    private final String entityId;

    public EidasAuthnRequestGenerator(String entityId) {
        this.entityId = entityId;
    }

    public AuthnRequest generateAuthnRequest(String authnReqeustId) {
        AuthnRequest eidasAuthnRequest = openSamlXmlObjectFactory.createAuthnRequest();
        eidasAuthnRequest.setID(authnReqeustId);
        eidasAuthnRequest.setConsent(StatusResponseType.UNSPECIFIED_CONSENT);
        eidasAuthnRequest.setForceAuthn(true);
        eidasAuthnRequest.setProviderName(PROVIDER_NAME);
        eidasAuthnRequest.setIssuer(openSamlXmlObjectFactory.createIssuer(entityId));

        NameIDPolicy nameIdPolicy = openSamlXmlObjectFactory.createNameIdPolicy();
        nameIdPolicy.setFormat(NameIDType.UNSPECIFIED);
        nameIdPolicy.setAllowCreate(true);
        eidasAuthnRequest.setNameIDPolicy(nameIdPolicy);

        RequestedAuthnContext requestedAuthnContext = openSamlXmlObjectFactory.createRequestedAuthnContext(AuthnContextComparisonTypeEnumeration.MINIMUM);
        requestedAuthnContext.getAuthnContextClassRefs().add(openSamlXmlObjectFactory.createAuthnContextClassReference(LevelOfAssurance.SUBSTANTIAL.toString()));
        eidasAuthnRequest.setRequestedAuthnContext(requestedAuthnContext);

        Extensions extensions = new ExtensionsBuilder().buildObject();
        eidasAuthnRequest.setExtensions(extensions);

        XMLObjectBuilder<?> builder = xmlObjectBuilderFactory.getBuilder(SPType.DEFAULT_ELEMENT_NAME);
        SPTypeImpl spTypeObject = (SPTypeImpl) builder.buildObject(SPType.DEFAULT_ELEMENT_NAME);
        spTypeObject.setValue("public");
        extensions.getUnknownXMLObjects().add(spTypeObject);

        return eidasAuthnRequest;
    }
}
