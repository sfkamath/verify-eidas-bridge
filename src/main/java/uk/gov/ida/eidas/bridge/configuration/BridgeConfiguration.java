package uk.gov.ida.eidas.bridge.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.Configuration;
import org.dhatim.dropwizard.jwt.cookie.authentication.JwtCookieAuthConfiguration;
import uk.gov.ida.saml.metadata.MetadataConfiguration;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class BridgeConfiguration extends Configuration {

    @JsonProperty
    @Valid
    private MetadataConfiguration verifyMetadata;

    @JsonProperty
    @Valid
    private MetadataConfiguration eidasMetadata;

    @JsonProperty
    @NotNull
    private String eidasNodeEntityId;

    @JsonProperty
    @NotNull
    private String bridgeEntityId;

    @JsonProperty
    @NotNull
    private String hostname;

    @JsonProperty("signingKeyStore")
    @Valid
    private SigningKeyStoreConfiguration signingKeyStoreConfiguration;

    @Valid
    @NotNull
    private JwtCookieAuthConfiguration sessionCookie = new JwtCookieAuthConfiguration();


    public MetadataConfiguration getVerifyMetadataConfiguration() {
        return verifyMetadata;
    }

    public MetadataConfiguration getEidasMetadataConfiguration() {
        return eidasMetadata;
    }

    public SigningKeyStoreConfiguration getSigningKeyStoreConfiguration() {
        return signingKeyStoreConfiguration;
    }

    public String getHostname() {
        return hostname;
    }

    public String getEidasNodeEntityId() {
        return eidasNodeEntityId;
    }

    public JwtCookieAuthConfiguration getSessionCookie() {
        return sessionCookie;
    }

    public String getBridgeEntityId() {
        return bridgeEntityId;
    }
}
