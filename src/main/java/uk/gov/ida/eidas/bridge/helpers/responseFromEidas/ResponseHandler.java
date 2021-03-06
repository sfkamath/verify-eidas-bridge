package uk.gov.ida.eidas.bridge.helpers.responseFromEidas;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.security.SecurityException;
import uk.gov.ida.eidas.bridge.domain.EidasIdentityAssertion;
import uk.gov.ida.eidas.bridge.domain.EidasSamlResponse;
import uk.gov.ida.saml.deserializers.StringToOpenSamlObjectTransformer;
import uk.gov.ida.saml.security.AssertionDecrypter;
import uk.gov.ida.saml.security.SamlAssertionsSignatureValidator;
import uk.gov.ida.saml.security.validators.ValidatedAssertions;
import uk.gov.ida.saml.security.validators.ValidatedResponse;
import uk.gov.ida.saml.security.validators.signature.SamlResponseSignatureValidator;

import java.util.List;

public class ResponseHandler {
    private final StringToOpenSamlObjectTransformer<Response> stringToResponse;
    private final SamlResponseSignatureValidator samlResponseSignatureValidator;
    private final AssertionDecrypter assertionDecrypter;
    private final SamlAssertionsSignatureValidator samlAssertionsSignatureValidator;
    private final EidasIdentityAssertionUnmarshaller eidasIdentityAssertionUnmarshaller;


    public ResponseHandler(StringToOpenSamlObjectTransformer<Response> stringToResponse,
                           SamlResponseSignatureValidator samlResponseSignatureValidator,
                           AssertionDecrypter assertionDecrypter,
                           SamlAssertionsSignatureValidator samlAssertionsSignatureValidator,
                           EidasIdentityAssertionUnmarshaller eidasIdentityAssertionUnmarshaller) {
        this.stringToResponse = stringToResponse;
        this.samlResponseSignatureValidator = samlResponseSignatureValidator;
        this.assertionDecrypter = assertionDecrypter;
        this.samlAssertionsSignatureValidator = samlAssertionsSignatureValidator;
        this.eidasIdentityAssertionUnmarshaller = eidasIdentityAssertionUnmarshaller;
    }

    public EidasSamlResponse handleResponse(String base64EncodedResponse, String expectedId, String eidasEntityId) throws SecurityException {
        Response response = this.stringToResponse.apply(base64EncodedResponse);

        if(!response.getInResponseTo().equals(expectedId)) {
            throw new SecurityException("Response InResponseTo (" + response.getInResponseTo() + ") didn't match expected id (" + expectedId + ")");
        }

        String actualIssuer = response.getIssuer().getValue();
        if(!eidasEntityId.equals(actualIssuer)) {
            throw new SecurityException("Response issuer (" + actualIssuer + ") didn't match expected issuer (" + eidasEntityId + ")");
        }

        ValidatedResponse validatedResponse = samlResponseSignatureValidator.validate(response, IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        List<Assertion> decryptedAssertions = assertionDecrypter.decryptAssertions(validatedResponse);
        ValidatedAssertions validatedAssertions = samlAssertionsSignatureValidator.validate(decryptedAssertions, IDPSSODescriptor.DEFAULT_ELEMENT_NAME);

        EidasIdentityAssertion eidasIdentityAssertion = eidasIdentityAssertionUnmarshaller.unmarshallAssertion(validatedAssertions);

        return new EidasSamlResponse(eidasIdentityAssertion);
    }
}
