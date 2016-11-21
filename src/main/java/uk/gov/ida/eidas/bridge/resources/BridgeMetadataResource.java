package uk.gov.ida.eidas.bridge.resources;

import com.google.common.base.Throwables;
import org.apache.http.client.utils.URIBuilder;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.saml2.metadata.impl.EntitiesDescriptorBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import uk.gov.ida.common.shared.security.Certificate;
import uk.gov.ida.eidas.bridge.configuration.BridgeConfiguration;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.metadata.transformers.KeyDescriptorsUnmarshaller;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.function.Function;

@Path("/")
@Produces(MediaType.APPLICATION_XML)
public class BridgeMetadataResource {
    BridgeConfiguration bridgeConfiguration;

    private final KeyDescriptorsUnmarshaller keyDescriptorsUnmarshaller;
    private final Function<EntitiesDescriptor, Element> entitiesDescriptorElementTransformer;
    Collection<Certificate> signingCertificates;

    public BridgeMetadataResource(BridgeConfiguration bridgeConfiguration, KeyDescriptorsUnmarshaller keyDescriptorsUnmarshaller, Function<EntitiesDescriptor, Element> entitiesDescriptorElementTransformer, Collection<Certificate> signingCertificates) {
        this.bridgeConfiguration = bridgeConfiguration;
        this.keyDescriptorsUnmarshaller = keyDescriptorsUnmarshaller;
        this.entitiesDescriptorElementTransformer = entitiesDescriptorElementTransformer;
        this.signingCertificates = signingCertificates;
    }

    @GET
    @Path("/metadata")
    public Document getMetadata() {
        EntitiesDescriptor entitiesDescriptor = new EntitiesDescriptorBuilder().buildObject();
        entitiesDescriptor.setValidUntil(DateTime.now().plusHours(1));

        final EntityDescriptor bridgeEntityDescriptor = createEntityDescriptor(bridgeConfiguration.getSamlConfiguration().getEntityId());
        final OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();
        bridgeEntityDescriptor.getRoleDescriptors().add(getIdpSsoDescriptor(openSamlXmlObjectFactory));
        entitiesDescriptor.getEntityDescriptors().add(bridgeEntityDescriptor);

        return entitiesDescriptorElementTransformer.apply(entitiesDescriptor).getOwnerDocument();
    }

    private EntityDescriptor createEntityDescriptor(String entityId) {
        XMLObjectBuilderFactory openSamlBuilderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
        EntityDescriptor entityDescriptor = (EntityDescriptor) openSamlBuilderFactory.getBuilder(EntityDescriptor.TYPE_NAME).buildObject(EntityDescriptor.DEFAULT_ELEMENT_NAME, EntityDescriptor.TYPE_NAME);
        entityDescriptor.setEntityID(entityId);
        return entityDescriptor;
    }

    private RoleDescriptor getIdpSsoDescriptor(OpenSamlXmlObjectFactory openSamlXmlObjectFactory) {
        IDPSSODescriptor idpssoDescriptor = openSamlXmlObjectFactory.createIDPSSODescriptor();
        idpssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        idpssoDescriptor.getSingleSignOnServices().add(getSsoService(openSamlXmlObjectFactory));
        idpssoDescriptor.getKeyDescriptors().addAll(keyDescriptorsUnmarshaller.fromCertificates(signingCertificates));

        return idpssoDescriptor;
    }

    private SingleSignOnService getSsoService(OpenSamlXmlObjectFactory openSamlXmlObjectFactory) {
        URI ssoLocation;
        try {
            ssoLocation = new URIBuilder(bridgeConfiguration.getHostname()).setPath(VerifyAuthnRequestResource.SINGLE_SIGN_ON_PATH).build();
        } catch (URISyntaxException e) {
            throw Throwables.propagate(e);
        }
        return openSamlXmlObjectFactory.createSingleSignOnService(
            SAMLConstants.SAML2_POST_BINDING_URI,
            ssoLocation.toString()
        );
    }

}
