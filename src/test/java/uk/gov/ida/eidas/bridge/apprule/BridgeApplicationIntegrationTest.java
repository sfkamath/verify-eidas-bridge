package uk.gov.ida.eidas.bridge.apprule;

import com.github.tomakehurst.wiremock.WireMockServer;
import io.dropwizard.testing.ConfigOverride;
import io.dropwizard.testing.DropwizardTestSupport;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import uk.gov.ida.eidas.bridge.BridgeApplication;
import uk.gov.ida.eidas.bridge.configuration.BridgeConfiguration;
import uk.gov.ida.eidas.bridge.testhelpers.TestSigningKeyStoreProvider;
import uk.gov.ida.saml.metadata.test.factories.metadata.MetadataFactory;

import java.util.function.Supplier;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;


public class BridgeApplicationIntegrationTest {

    private static final WireMockServer wireMock = new WireMockServer(wireMockConfig().dynamicPort());

    private static final String KEYSTORE_PASSWORD = "fooBar";
    private static final String ALIAS = "key-alias";
    private static final String eidasEncodedSigningKeyStore = TestSigningKeyStoreProvider.getBase64EncodedKeyStore(ALIAS, KEYSTORE_PASSWORD);
    private static final String verifyEncodedSigningKeyStore = TestSigningKeyStoreProvider.getBase64EncodedKeyStore(ALIAS, KEYSTORE_PASSWORD);
    private static final String encodedEncryptingKeyStore = TestSigningKeyStoreProvider.getBase64EncodedKeyStore(ALIAS, KEYSTORE_PASSWORD);

    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final DropwizardTestSupport<BridgeConfiguration> dropwizardTestSupport = new DropwizardTestSupport<>(BridgeApplication.class,
        "eidasbridge-test.yml",
        ConfigOverride.config("verifyMetadata.trustStorePath", "test_metadata_truststore.ts"),
        ConfigOverride.config("verifyMetadata.uri", () -> "http://localhost:" + wireMock.port() + "/SAML2/metadata/federation"),
        ConfigOverride.config("eidasMetadata.trustStorePath", "test_metadata_truststore.ts"),
        ConfigOverride.config("eidasMetadata.uri", nodeMetadataUri()),
        ConfigOverride.config("eidasNodeEntityId", nodeMetadataUri()),
        ConfigOverride.config("eidasSigningKeyStore.base64Value", eidasEncodedSigningKeyStore),
        ConfigOverride.config("eidasSigningKeyStore.password", KEYSTORE_PASSWORD),
        ConfigOverride.config("eidasSigningKeyStore.type", KEYSTORE_TYPE),
        ConfigOverride.config("eidasSigningKeyStore.alias", ALIAS),
        ConfigOverride.config("verifySigningKeyStore.base64Value", verifyEncodedSigningKeyStore),
        ConfigOverride.config("verifySigningKeyStore.password", KEYSTORE_PASSWORD),
        ConfigOverride.config("verifySigningKeyStore.type", KEYSTORE_TYPE),
        ConfigOverride.config("verifySigningKeyStore.alias", ALIAS),
        ConfigOverride.config("encryptingKeyStore.base64Value", encodedEncryptingKeyStore),
        ConfigOverride.config("encryptingKeyStore.password", KEYSTORE_PASSWORD),
        ConfigOverride.config("encryptingKeyStore.type", KEYSTORE_TYPE),
        ConfigOverride.config("encryptingKeyStore.alias", ALIAS),
        ConfigOverride.config("hostname", "www.example.com")
    );

    private static Supplier<String> nodeMetadataUri() {
        return () -> "http://localhost:" + wireMock.port() + "/ServiceMetadata";
    }

    @Before
    public void before() {
        wireMock.start();
    }

    @After
    public void after() {
        wireMock.stop();
        dropwizardTestSupport.after();
    }

    @Test
    public void shouldRequestMetadataFromVerifyAndEidasOnStartup() throws Exception {
        wireMock.stubFor(
            get(urlEqualTo("/SAML2/metadata/federation"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/xml")
                    .withBody(new MetadataFactory().defaultMetadata())
                )
        );
        wireMock.stubFor(
            get(urlEqualTo("/ServiceMetadata"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "text/xml")
                    .withBody(new MetadataFactory().defaultMetadata())
                )
        );

        // Start the application
        dropwizardTestSupport.before();

        wireMock.verify(getRequestedFor(urlEqualTo("/SAML2/metadata/federation")));
        wireMock.verify(getRequestedFor(urlEqualTo("/ServiceMetadata")));
    }
}
