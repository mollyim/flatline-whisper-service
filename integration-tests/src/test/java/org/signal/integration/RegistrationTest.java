/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.integration;

import io.micrometer.common.util.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.entities.CreateVerificationSessionRequest;
import org.whispersystems.textsecuregcm.entities.SubmitVerificationCodeRequest;
import org.whispersystems.textsecuregcm.entities.UpdateVerificationSessionRequest;
import org.whispersystems.textsecuregcm.entities.VerificationCodeRequest;
import org.whispersystems.textsecuregcm.entities.CreateVerificationSessionResponse;

public class RegistrationTest {

  @Test
  public void testRegistration() throws Exception {
    final UpdateVerificationSessionRequest originalRequest = new UpdateVerificationSessionRequest(
        "test", UpdateVerificationSessionRequest.PushTokenType.FCM, null, null, null, null);

    final Operations.PrescribedVerificationPrincipal params = Operations.prescribedVerificationPrincipal();
    final CreateVerificationSessionRequest input = new CreateVerificationSessionRequest(params.principal(),
        originalRequest);

    final CreateVerificationSessionResponse createVerificationSessionResponse = Operations
        .apiPost("/v1/verification/session", input)
        .executeExpectSuccess(CreateVerificationSessionResponse.class);

    final String sessionId = createVerificationSessionResponse.id();
    Assertions.assertTrue(StringUtils.isNotBlank(sessionId));

    final String pushChallenge = Operations.peekVerificationSessionPushChallenge(sessionId);

    // supply push challenge
    final UpdateVerificationSessionRequest updatedRequest = new UpdateVerificationSessionRequest(
        "test", UpdateVerificationSessionRequest.PushTokenType.FCM, pushChallenge, null, null, null);
    final CreateVerificationSessionResponse pushChallengeSupplied = Operations
        .apiPatch("/v1/verification/session/%s".formatted(sessionId), updatedRequest)
        .executeExpectSuccess(CreateVerificationSessionResponse.class);

    Assertions.assertTrue(pushChallengeSupplied.allowedToRequestCode());

    // request code
    final VerificationCodeRequest verificationCodeRequest = new VerificationCodeRequest(
        VerificationCodeRequest.Transport.SMS, "android-ng");

    final CreateVerificationSessionResponse codeRequested = Operations
        .apiPost("/v1/verification/session/%s/code".formatted(sessionId), verificationCodeRequest)
        .executeExpectSuccess(CreateVerificationSessionResponse.class);

    // verify code
    final SubmitVerificationCodeRequest submitVerificationCodeRequest = new SubmitVerificationCodeRequest(
        params.verificationCode());
    final CreateVerificationSessionResponse codeVerified = Operations
        .apiPut("/v1/verification/session/%s/code".formatted(sessionId), submitVerificationCodeRequest)
        .executeExpectSuccess(CreateVerificationSessionResponse.class);
  }
}
