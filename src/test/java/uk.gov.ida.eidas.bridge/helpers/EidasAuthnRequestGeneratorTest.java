package uk.gov.ida.eidas.bridge.helpers;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.StatusResponseType;
import uk.gov.ida.saml.core.IdaSamlBootstrap;

public class EidasAuthnRequestGeneratorTest {

    @Before
    public void bootStrapOpenSaml() {
        IdaSamlBootstrap.bootstrap();
    }
    
    @Test
    public void shouldGenerateAnEidasAuthnRequest() {
        String entityId = "http://i.am.the.bridge.com";
        EidasAuthnRequestGenerator earg = new EidasAuthnRequestGenerator(entityId);
        AuthnRequest authnRequest = earg.generateAuthnRequest("aTestId");
        Assert.assertNotNull(authnRequest);
        Assert.assertEquals("aTestId", authnRequest.getID());
        Assert.assertEquals(StatusResponseType.UNSPECIFIED_CONSENT, authnRequest.getConsent());
        Assert.assertEquals(true, authnRequest.isForceAuthn());
        Assert.assertEquals(false, authnRequest.isPassive());
        Assert.assertEquals(SAMLVersion.VERSION_20, authnRequest.getVersion());
        Assert.assertEquals(EidasAuthnRequestGenerator.PROVIDER_NAME, authnRequest.getProviderName());

        Issuer issuer = authnRequest.getIssuer();
        Assert.assertEquals(entityId, issuer.getValue());
    }
}
