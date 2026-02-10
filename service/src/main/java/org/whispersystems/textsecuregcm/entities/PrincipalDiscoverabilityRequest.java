package org.whispersystems.textsecuregcm.entities;

import jakarta.validation.constraints.NotNull;

public record PrincipalDiscoverabilityRequest(@NotNull Boolean discoverableByPrincipal) {}
