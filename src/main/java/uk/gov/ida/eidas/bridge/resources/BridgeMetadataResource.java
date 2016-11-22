package uk.gov.ida.eidas.bridge.resources;

import com.google.common.base.Throwables;
import org.apache.http.client.utils.URIBuilder;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.saml2.metadata.impl.EntitiesDescriptorBuilder;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
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
    private final Collection<Certificate> signingCertificates;
    private final BasicCredential signingCredential;
    private final X509Credential x509SigningCredential;
    private final KeyInfoGenerator keyInfoGenerator;

    public BridgeMetadataResource(BridgeConfiguration bridgeConfiguration,
                                  KeyDescriptorsUnmarshaller keyDescriptorsUnmarshaller,
                                  Function<EntitiesDescriptor, Element> entitiesDescriptorElementTransformer,
                                  Collection<Certificate> signingCertificates,
                                  BasicCredential signingCredential,
                                  X509Credential x509SigningCredential) {
        this.bridgeConfiguration = bridgeConfiguration;
        this.keyDescriptorsUnmarshaller = keyDescriptorsUnmarshaller;
        this.entitiesDescriptorElementTransformer = entitiesDescriptorElementTransformer;
        this.signingCertificates = signingCertificates;
        this.signingCredential = signingCredential;
        this.x509SigningCredential = x509SigningCredential;

        X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        keyInfoGeneratorFactory.setEmitEntityCertificate(true);
        keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
    }

    @GET
    @Path("/metadata")
    public Document getMetadata() throws MarshallingException, SignatureException, SecurityException {
        EntitiesDescriptor entitiesDescriptor = new EntitiesDescriptorBuilder().buildObject();
        entitiesDescriptor.setValidUntil(DateTime.now().plusHours(1));

        final EntityDescriptor bridgeEntityDescriptor = createEntityDescriptor(bridgeConfiguration.getSamlConfiguration().getEntityId());
        final OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();
        bridgeEntityDescriptor.getRoleDescriptors().add(getIdpSsoDescriptor(openSamlXmlObjectFactory));
        entitiesDescriptor.getEntityDescriptors().add(bridgeEntityDescriptor);

        Signature entityDescriptorSignature = openSamlXmlObjectFactory.createSignature();
        entityDescriptorSignature.setKeyInfo(keyInfoGenerator.generate(x509SigningCredential));
        entityDescriptorSignature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512);
        entityDescriptorSignature.setSigningCredential(signingCredential);
        bridgeEntityDescriptor.setSignature(entityDescriptorSignature);

        //noinspection ConstantConditions
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(entitiesDescriptor).marshall(entitiesDescriptor);
        Signer.signObject(entityDescriptorSignature);

        Signature entitiesDescriptorSignature = openSamlXmlObjectFactory.createSignature();
        entitiesDescriptorSignature.setKeyInfo(keyInfoGenerator.generate(x509SigningCredential));
        entitiesDescriptorSignature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512);
        entitiesDescriptorSignature.setSigningCredential(signingCredential);
        entitiesDescriptor.setSignature(entitiesDescriptorSignature);

        //noinspection ConstantConditions
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(entitiesDescriptor).marshall(entitiesDescriptor);
        Signer.signObject(entitiesDescriptorSignature);

        return entitiesDescriptorElementTransformer.apply(entitiesDescriptor).getOwnerDocument();
    }

    private EntityDescriptor createEntityDescriptor(String entityId) {
        XMLObjectBuilderFactory openSamlBuilderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
        EntityDescriptor entityDescriptor = (EntityDescriptor) openSamlBuilderFactory.getBuilder(EntityDescriptor.TYPE_NAME).buildObject(EntityDescriptor.DEFAULT_ELEMENT_NAME, EntityDescriptor.TYPE_NAME);
        entityDescriptor.setEntityID(entityId);
        return entityDescriptor;
    }

    private RoleDescriptor getIdpSsoDescriptor(OpenSamlXmlObjectFactory openSamlXmlObjectFactory) throws SignatureException, MarshallingException, SecurityException {
        IDPSSODescriptor idpssoDescriptor = openSamlXmlObjectFactory.createIDPSSODescriptor();
        idpssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        idpssoDescriptor.getSingleSignOnServices().add(getSsoService(openSamlXmlObjectFactory));
        idpssoDescriptor.getKeyDescriptors().addAll(keyDescriptorsUnmarshaller.fromCertificates(signingCertificates));

        Signature idpSsoDescriptorSignature = openSamlXmlObjectFactory.createSignature();
        idpSsoDescriptorSignature.setKeyInfo(keyInfoGenerator.generate(x509SigningCredential));
        idpSsoDescriptorSignature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512);
        idpSsoDescriptorSignature.setSigningCredential(signingCredential);
        idpssoDescriptor.setSignature(idpSsoDescriptorSignature);

        //noinspection ConstantConditions
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(idpssoDescriptor).marshall(idpssoDescriptor);
        Signer.signObject(idpSsoDescriptorSignature);

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
