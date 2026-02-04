/*
 * Copyright 2025 Molly Instant Messenger
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.entities;

import io.swagger.v3.oas.annotations.media.Schema;

public record CreateVerificationSessionResponse(
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "A URL-safe ID for the verification session")
    String id,

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Location of the authorization endpoint for the verification provider chosen by the client")
    String authorizationEndpoint,

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Identifier of the client requesting verification to be used in PAR")
    String clientId,

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Location of the pushed authorization request")
    String requestUri,

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Seconds to expiration of the pushed authorization request")
    long requestUriLifetime,

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Whether this session is verified")
    boolean verified) {

}
