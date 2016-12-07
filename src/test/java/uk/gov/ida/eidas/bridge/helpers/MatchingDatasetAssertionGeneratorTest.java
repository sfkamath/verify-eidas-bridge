package uk.gov.ida.eidas.bridge.helpers;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import uk.gov.ida.eidas.bridge.domain.EidasIdentityAssertion;
import uk.gov.ida.saml.core.domain.Gender;
import uk.gov.ida.saml.core.extensions.Address;
import uk.gov.ida.saml.core.extensions.StringBasedMdsAttributeValue;
import uk.gov.ida.saml.serializers.XmlObjectToBase64EncodedStringTransformer;

import java.util.List;

import static org.junit.Assert.assertEquals;

public class MatchingDatasetAssertionGeneratorTest {

    private static final String BRIDGE_ENTITY_ID = "bridgeEntityId";
    private static final String IN_RESPONSE_TO = "guid";

    private static final String FAMILY_NAME = "familyName";
    private static final String FIRST_NAME = "aFirstName";
    private static final String CURRENT_ADDRESS = "holborn";
    private static final Gender GENDER = Gender.MALE;
    private static final String DATE_OF_BIRTH = "1965-01-01";

    private MatchingDatasetAssertionGenerator mdag;

    @Before
    public void before() {
        EidasSamlBootstrap.bootstrap();
        mdag = new MatchingDatasetAssertionGenerator(BRIDGE_ENTITY_ID);
    }

    @Test
    public void generateIssuerAndSubject() throws Exception {
        EidasIdentityAssertion eidasIdentityAssertion = new EidasIdentityAssertion(FIRST_NAME, FAMILY_NAME, CURRENT_ADDRESS, GENDER, new DateTime(1965, 1, 1, 0, 0));
        Assertion assertion = mdag.generate(IN_RESPONSE_TO, eidasIdentityAssertion);

        assertEquals(BRIDGE_ENTITY_ID, assertion.getIssuer().getValue());
        Subject subject = assertion.getSubject();
        List<SubjectConfirmation> subjectConfirmations = subject.getSubjectConfirmations();
        SubjectConfirmation subjectConfirmation = subjectConfirmations.get(0);
        SubjectConfirmationData subjectConfirmationData = subjectConfirmation.getSubjectConfirmationData();
        assertEquals(IN_RESPONSE_TO, subjectConfirmationData.getInResponseTo());

    }

    @Test
    public void generateAttributeStatement() throws Exception {
        DateTime dateOfBirth = new DateTime(1965, 1, 1, 0, 0);
        EidasIdentityAssertion eidasIdentityAssertion = new EidasIdentityAssertion(FIRST_NAME, FAMILY_NAME, CURRENT_ADDRESS, GENDER, dateOfBirth);

        Assertion assertion = mdag.generate(IN_RESPONSE_TO, eidasIdentityAssertion);

        String apply = new XmlObjectToBase64EncodedStringTransformer<Assertion>().apply(assertion);

        List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
        AttributeStatement attributeStatement = attributeStatements.get(0);
        List<Attribute> attributes = attributeStatement.getAttributes();

        assertEquals(FIRST_NAME, getAttributeValueString(attributes, "MDS_firstname"));
        assertEquals(FAMILY_NAME, getAttributeValueString(attributes, "MDS_surname"));
        assertEquals(GENDER.getValue(), getAttributeValueString(attributes, "MDS_gender"));
        assertEquals(CURRENT_ADDRESS, ((Address)getAttributeValue(attributes, "MDS_currentaddress")).getLines().get(0).getValue());
        assertEquals(DATE_OF_BIRTH, getAttributeValueString(attributes, "MDS_dateofbirth"));
    }

    private XMLObject getAttributeValue(List<Attribute> attributes, String name) {
        return attributes.stream()
            .filter(x -> x.getName().equals(name))
            .findFirst()
            .flatMap(x -> (x.getAttributeValues().stream().findFirst()))
            .orElse(null);
    }

    private String getAttributeValueString(List<Attribute> attributes, String name) {
        return ((StringBasedMdsAttributeValue)getAttributeValue(attributes, name)).getValue();
    }


}
