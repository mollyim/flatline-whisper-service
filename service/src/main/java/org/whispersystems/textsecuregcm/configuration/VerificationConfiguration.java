/*
 * Copyright 2021 Signal Messenger, LLC
 * Copyright 2025 Molly Instant Messenger
 */

package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import io.dropwizard.validation.ValidationMethod;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class VerificationConfiguration {
  private final List<VerificationProviderConfiguration> providers;

  @JsonCreator
  public VerificationConfiguration(
      @JsonProperty("providers") @JsonSetter(nulls = Nulls.AS_EMPTY) final List<VerificationProviderConfiguration> providers){
    this.providers = Objects.requireNonNull(providers);
  }

  @Valid
  @NotNull
  public List<VerificationProviderConfiguration> getProviders() {
    return providers;
  }

  @JsonIgnore
  @ValidationMethod(message = "contains less than one verification provider")
  public boolean containsOneProvider() {
    return !providers.isEmpty();
  }

  @JsonIgnore
  @ValidationMethod(message = "contains multiple verification providers with the same name")
  public boolean containsUniqueProviderNames() {
    Set<String> found = new HashSet<>();
    for (VerificationProviderConfiguration provider : providers) {
      String name = provider.getName();
      if (!found.add(name)) {
        return false;
      }
    }
    return true;
  }

  @JsonIgnore
  public VerificationProviderConfiguration getProvider(String id) {
    for (VerificationProviderConfiguration provider : providers) {
      if (id.equals(provider.getId())) {
        return provider;
      }
    }
    return null;
  }
}
