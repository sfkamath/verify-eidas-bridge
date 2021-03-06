package uk.gov.ida.eidas.bridge.helpers.responseFromEidas;

import uk.gov.ida.saml.deserializers.validators.SizeValidator;
import uk.gov.ida.saml.hub.validators.StringSizeValidator;

public class ResponseSizeValidator implements SizeValidator {
    private static final int LOWER_BOUND = 1400;
    private static final int UPPER_BOUND = 50000;

    private final StringSizeValidator validator;

    public ResponseSizeValidator(StringSizeValidator validator) {
        this.validator = validator;
    }

    @Override
    public void validate(String input) {
        validator.validate(input, LOWER_BOUND, UPPER_BOUND);
    }

}
