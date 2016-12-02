package uk.gov.ida.eidas.bridge.resources;

import com.google.common.base.Throwables;
import io.dropwizard.auth.Auth;
import io.dropwizard.views.View;
import org.dhatim.dropwizard.jwt.cookie.authentication.DefaultJwtCookiePrincipal;
import org.opensaml.security.SecurityException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.eidas.bridge.domain.EidasSamlResponse;
import uk.gov.ida.eidas.bridge.helpers.AssertionConsumerServiceLocator;
import uk.gov.ida.eidas.bridge.helpers.ResponseHandler;
import uk.gov.ida.eidas.bridge.helpers.VerifyResponseGenerator;
import uk.gov.ida.eidas.bridge.views.ResponseFormView;
import uk.gov.ida.saml.core.validation.SamlTransformationErrorException;
import uk.gov.ida.saml.serializers.XmlObjectToBase64EncodedStringTransformer;

import javax.validation.constraints.NotNull;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

@Path("/")
public class EidasResponseResource {
    private static final Logger LOG = LoggerFactory.getLogger(EidasResponseResource.class);
    public final static String ASSERTION_CONSUMER_PATH = "/SAML2/SSO/Response/POST";
    //public final static String REDIRECT_TO_VERIFY_PATH = "/redirect-to-verify";

    private final String verifyEntityId;
    private final XmlObjectToBase64EncodedStringTransformer xmlObjectToBase64EncodedStringTransformer;
    private final ResponseHandler responseHandler;
    private final VerifyResponseGenerator responseGenerator;
    private final AssertionConsumerServiceLocator assertionConsumerServiceLocator;

    public EidasResponseResource(
        String verifyEntityId, XmlObjectToBase64EncodedStringTransformer xmlObjectToBase64EncodedStringTransformer,
        ResponseHandler responseHandler,
        VerifyResponseGenerator responseGenerator,
        AssertionConsumerServiceLocator assertionConsumerServiceLocator) {
        this.verifyEntityId = verifyEntityId;
        this.xmlObjectToBase64EncodedStringTransformer = xmlObjectToBase64EncodedStringTransformer;
        this.responseHandler = responseHandler;
        this.responseGenerator = responseGenerator;
        this.assertionConsumerServiceLocator = assertionConsumerServiceLocator;
    }

    @POST
    @Path(ASSERTION_CONSUMER_PATH)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public View handleEidasResponseAndTranslateIntoVerifyResponse(
        @FormParam("SAMLResponse") @NotNull String responseStr,
        @Auth DefaultJwtCookiePrincipal principal) {
        String outboundID = principal.getClaims().get("outboundID", String.class);

        EidasSamlResponse eidasSamlResponse;
        try {
            eidasSamlResponse = responseHandler.handleResponse(responseStr, outboundID);
        } catch (SamlTransformationErrorException | SignatureException | SecurityException e) {
            LOG.error("Could not validate signature on Response", e);
            throw Throwables.propagate(e); // TODO - return 400 from here somewhere
        }

        String inboundID = principal.getClaims().get("inboundID", String.class);
        String assertionConsumerServiceLocation = assertionConsumerServiceLocator.getAssertionConsumerServiceLocation(verifyEntityId);
        org.opensaml.saml.saml2.core.Response response = responseGenerator.generateResponse(assertionConsumerServiceLocation, inboundID, eidasSamlResponse.getIdentityAssertion());
        return new ResponseFormView(xmlObjectToBase64EncodedStringTransformer.apply(response), assertionConsumerServiceLocation);
    }
}
