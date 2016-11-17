package uk.gov.ida.eidas.bridge.helpers;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import uk.gov.ida.eidas.saml.extensions.SPType;
import uk.gov.ida.eidas.saml.extensions.SPTypeBuilder;
import uk.gov.ida.eidas.saml.extensions.SPTypeImpl;
import uk.gov.ida.saml.core.IdaSamlBootstrap;

public class EidasSamlBootstrap {

    private EidasSamlBootstrap () { }

    public static void bootstrap() {
        IdaSamlBootstrap.bootstrap();
        XMLObjectProviderRegistrySupport.registerObjectProvider(SPType.DEFAULT_ELEMENT_NAME, new SPTypeBuilder(), SPTypeImpl.MARSHALLER, SPTypeImpl.UNMARSHALLER);
    }

}
