/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.entities;

import java.util.List;
import javax.annotation.Nullable;
import io.swagger.v3.oas.annotations.media.Schema;
import org.whispersystems.textsecuregcm.registration.VerificationSession;

public record VerificationSessionResponse(
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "A URL-safe ID for the verification session")
    String id,

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Location of the authorization endpoint for the verification provider chosen by the client")
    String authorizationEndpoint,

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Identifier of the client requesting verification to be used in PAR")
    String clientId,

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Location of the stored authorization request at the PAR endpoint")
    String requestUri,

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Seconds to expiration of the the PAR endpoint")
    int requestUriExpiresSeconds,

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Whether this session is verified")
    boolean verified) {

}
