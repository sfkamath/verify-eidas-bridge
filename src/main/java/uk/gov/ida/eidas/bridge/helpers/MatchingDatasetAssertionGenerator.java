package uk.gov.ida.eidas.bridge.helpers;

import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationDataBuilder;
import uk.gov.ida.eidas.bridge.domain.EidasIdentityAssertion;
import uk.gov.ida.saml.core.extensions.Address;
import uk.gov.ida.saml.core.extensions.Line;
import uk.gov.ida.saml.core.extensions.StringBasedMdsAttributeValue;
import uk.gov.ida.saml.core.extensions.impl.AddressBuilder;
import uk.gov.ida.saml.core.extensions.impl.LineBuilder;
import uk.gov.ida.saml.core.extensions.impl.StringBasedMdsAttributeValueBuilder;

import java.util.List;

public class MatchingDatasetAssertionGenerator {
    private final String bridgeEntityId;
    private static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormat.forPattern("YYYY-MM-DD");

    public MatchingDatasetAssertionGenerator(String bridgeEntityId) {
        this.bridgeEntityId = bridgeEntityId;
    }

    public Assertion generate(String inResponseTo, EidasIdentityAssertion eidasIdentityAssertion) {
        Assertion assertion = new AssertionBuilder().buildObject();

        setIssuer(assertion);
        setSubject(inResponseTo, assertion);
        setAttributeStatement(assertion, eidasIdentityAssertion);

        return assertion;
    }

    private void setAttributeStatement(Assertion assertion, EidasIdentityAssertion eidasIdentityAssertion) {
        AttributeStatement attributeStatement = new AttributeStatementBuilder().buildObject();

        List<Attribute> attributes = attributeStatement.getAttributes();
        attributes.add(getAttribute("Firstname", "MDS_firstname", eidasIdentityAssertion.getFirstName()));
        attributes.add(getAttribute("Surname", "MDS_surname", eidasIdentityAssertion.getFamilyName()));
        attributes.add(getAttribute("Gender", "MDS_gender", eidasIdentityAssertion.getGender().getValue()));


        attributes.add(getAttribute("Date of Birth", "MDS_dateofbirth", DATE_TIME_FORMATTER.print(eidasIdentityAssertion.getDateOfBirth())));

        Attribute addressAttribute = new AttributeBuilder().buildObject();
        addressAttribute.setFriendlyName("Current Address");
        addressAttribute.setName("MDS_currentaddress");
        Address address = new AddressBuilder().buildObject();
        addressAttribute.getAttributeValues().add(address);
        Line line = new LineBuilder().buildObject();
        line.setValue(eidasIdentityAssertion.getCurrentAddress());
        address.getLines().add(line);
        attributes.add(addressAttribute);

        assertion.getAttributeStatements().add(attributeStatement);
    }

    private Attribute getAttribute(String friendlyName, String name, String value) {
        Attribute attribute = new AttributeBuilder().buildObject();
        attribute.setFriendlyName(friendlyName);
        attribute.setName(name);
        StringBasedMdsAttributeValue mdsAttributeValue = new StringBasedMdsAttributeValueBuilder().buildObject();
        mdsAttributeValue.setValue(value);
        attribute.getAttributeValues().add(mdsAttributeValue);
        return attribute;
    }

    private void setSubject(String inResponseTo, Assertion assertion) {
        Subject subject = new SubjectBuilder().buildObject();
        SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder().buildObject();
        SubjectConfirmationData subjectConfirmationData = new SubjectConfirmationDataBuilder().buildObject();
        subjectConfirmationData.setInResponseTo(inResponseTo);
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subject.getSubjectConfirmations().add(subjectConfirmation);
        assertion.setSubject(subject);
    }

    private void setIssuer(Assertion assertion) {
        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue(bridgeEntityId);
        assertion.setIssuer(issuer);
    }
}
