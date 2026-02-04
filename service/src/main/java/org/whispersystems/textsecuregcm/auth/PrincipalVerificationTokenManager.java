/*
 * Copyright 2023 Signal Messenger, LLC
 * Copyright 2025 Molly Instant Messenger
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.auth;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.ServerErrorException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Response;
import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.entities.PrincipalVerificationDetails;
import org.whispersystems.textsecuregcm.entities.PrincipalVerificationRequest;
import org.whispersystems.textsecuregcm.registration.VerificationSession;
import org.whispersystems.textsecuregcm.spam.RegistrationRecoveryChecker;
import org.whispersystems.textsecuregcm.storage.PrincipalNameIdentifiers;
import org.whispersystems.textsecuregcm.storage.RegistrationRecoveryPasswordsManager;
import org.whispersystems.textsecuregcm.storage.VerificationSessionManager;

public class PrincipalVerificationTokenManager {

  private static final Logger logger = LoggerFactory.getLogger(PrincipalVerificationTokenManager.class);
  private static final Duration REGISTRATION_RPC_TIMEOUT = Duration.ofSeconds(15);
  private static final long VERIFICATION_TIMEOUT_SECONDS = REGISTRATION_RPC_TIMEOUT.plusSeconds(1).getSeconds();

  private final PrincipalNameIdentifiers principalNameIdentifiers;

  private final VerificationSessionManager verificationSessionManager;
  private final RegistrationRecoveryPasswordsManager registrationRecoveryPasswordsManager;
  private final RegistrationRecoveryChecker registrationRecoveryChecker;

  public PrincipalVerificationTokenManager(final PrincipalNameIdentifiers principalNameIdentifiers,
                                           final VerificationSessionManager verificationSessionManager,
                                           final RegistrationRecoveryPasswordsManager registrationRecoveryPasswordsManager,
                                           final RegistrationRecoveryChecker registrationRecoveryChecker) {
    this.principalNameIdentifiers = principalNameIdentifiers;
    this.verificationSessionManager = verificationSessionManager;
    this.registrationRecoveryPasswordsManager = registrationRecoveryPasswordsManager;
    this.registrationRecoveryChecker = registrationRecoveryChecker;
  }

  /**
   * Checks if a {@link PrincipalVerificationRequest} has a token that verifies the caller has confirmed access to the
   * principal and returns how the principal has been verified
   *
   * @param requestContext the container request context
   * @param principal the principal presented for verification
   * @param request the request with exactly one verification token (verification session ID or registration
   *                recovery password)
   * @return if verification was successful, returns the verification type
   * @throws BadRequestException    if the principal does not match the sessionId’s principal, or the remote service
   *                                rejects the session ID as invalid
   * @throws NotAuthorizedException if the session is not verified
   * @throws ForbiddenException     if the recovery password is not valid
   * @throws InterruptedException   if verification did not complete before a timeout
   */
  public PrincipalVerificationDetails verify(final ContainerRequestContext requestContext, final String principal, final PrincipalVerificationRequest request)
      throws InterruptedException {

    final PrincipalVerificationRequest.VerificationType verificationType = request.verificationType();
    PrincipalVerificationDetails verificationDetails = null;
    switch (verificationType) {
      case SESSION -> verificationDetails = verifyBySessionId(principal, request.sessionId());
      case RECOVERY_PASSWORD -> verificationDetails = verifyByRecoveryPassword(requestContext, principal, request.recoveryPassword());
    }

    return verificationDetails;
  }

  private PrincipalVerificationDetails verifyBySessionId(final String principal, final String sessionId) throws InterruptedException {
    final VerificationSession session = verificationSessionManager.findForId(sessionId)
        .orTimeout(5, TimeUnit.SECONDS)
        .join().orElseThrow(NotFoundException::new);

    if (!principal.equals(session.principal())) {
      throw new BadRequestException("principal does not match session");
    }

    if (!session.verified()) {
      throw new NotAuthorizedException("session not verified");
    }

    return new PrincipalVerificationDetails(PrincipalVerificationDetails.VerificationType.SESSION,
        session.providerId(), session.subject(), principal);
  }

  private PrincipalVerificationDetails verifyByRecoveryPassword(final ContainerRequestContext requestContext, final String principal, final byte[] recoveryPassword)
      throws InterruptedException {
    if (!registrationRecoveryChecker.checkRegistrationRecoveryAttempt(requestContext, principal)) {
      throw new ForbiddenException("recoveryPassword couldn't be verified");
    }
    try {
      final boolean verified = registrationRecoveryPasswordsManager.verify(
              principalNameIdentifiers.getPrincipalNameIdentifier(principal).join(), recoveryPassword)
          .get(VERIFICATION_TIMEOUT_SECONDS, TimeUnit.SECONDS);
      if (!verified) {
        throw new ForbiddenException("recoveryPassword couldn't be verified");
      }
    } catch (final ExecutionException | TimeoutException e) {
      throw new ServerErrorException(Response.Status.SERVICE_UNAVAILABLE);
    }

    return new PrincipalVerificationDetails(PrincipalVerificationDetails.VerificationType.RECOVERY_PASSWORD, principal);
  }

}
