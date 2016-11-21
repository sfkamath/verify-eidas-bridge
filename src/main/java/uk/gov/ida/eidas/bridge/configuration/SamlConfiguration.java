package uk.gov.ida.eidas.bridge.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;

import javax.validation.constraints.NotNull;

public class SamlConfiguration {
    @JsonProperty
    @NotNull
    private String entityId;

    public String getEntityId() {
        return entityId;
    }
}
