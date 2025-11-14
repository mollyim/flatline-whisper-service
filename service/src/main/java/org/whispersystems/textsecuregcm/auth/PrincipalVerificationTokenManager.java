/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.auth;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.ServerErrorException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Response;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.entities.PrincipalVerificationRequest;
import org.whispersystems.textsecuregcm.entities.RegistrationServiceSession;
import org.whispersystems.textsecuregcm.registration.RegistrationServiceClient;
import org.whispersystems.textsecuregcm.spam.RegistrationRecoveryChecker;
import org.whispersystems.textsecuregcm.storage.PrincipalNameIdentifiers;
import org.whispersystems.textsecuregcm.storage.RegistrationRecoveryPasswordsManager;

public class PrincipalVerificationTokenManager {

  private static final Logger logger = LoggerFactory.getLogger(PrincipalVerificationTokenManager.class);
  private static final Duration REGISTRATION_RPC_TIMEOUT = Duration.ofSeconds(15);
  private static final long VERIFICATION_TIMEOUT_SECONDS = REGISTRATION_RPC_TIMEOUT.plusSeconds(1).getSeconds();

  private final PrincipalNameIdentifiers principalNameIdentifiers;

  private final RegistrationServiceClient registrationServiceClient;
  private final RegistrationRecoveryPasswordsManager registrationRecoveryPasswordsManager;
  private final RegistrationRecoveryChecker registrationRecoveryChecker;

  public PrincipalVerificationTokenManager(final PrincipalNameIdentifiers principalNameIdentifiers,
                                           final RegistrationServiceClient registrationServiceClient,
                                           final RegistrationRecoveryPasswordsManager registrationRecoveryPasswordsManager,
                                           final RegistrationRecoveryChecker registrationRecoveryChecker) {
    this.principalNameIdentifiers = principalNameIdentifiers;
    this.registrationServiceClient = registrationServiceClient;
    this.registrationRecoveryPasswordsManager = registrationRecoveryPasswordsManager;
    this.registrationRecoveryChecker = registrationRecoveryChecker;
  }

  /**
   * Checks if a {@link PrincipalVerificationRequest} has a token that verifies the caller has confirmed access to the
   * principal
   *
   * @param requestContext the container request context
   * @param principal the principal presented for verification
   * @param request the request with exactly one verification token (RegistrationService sessionId or registration
   *                recovery password)
   * @return if verification was successful, returns the verification type
   * @throws BadRequestException    if the principal does not match the sessionId’s principal, or the remote service
   *                                rejects the session ID as invalid
   * @throws NotAuthorizedException if the session is not verified
   * @throws ForbiddenException     if the recovery password is not valid
   * @throws InterruptedException   if verification did not complete before a timeout
   */
  public PrincipalVerificationRequest.VerificationType verify(final ContainerRequestContext requestContext, final String principal, final PrincipalVerificationRequest request)
      throws InterruptedException {

    final PrincipalVerificationRequest.VerificationType verificationType = request.verificationType();
    switch (verificationType) {
      case SESSION -> verifyBySessionId(principal, request.decodeSessionId());
      case RECOVERY_PASSWORD -> verifyByRecoveryPassword(requestContext, principal, request.recoveryPassword());
    }

    return verificationType;
  }

  private void verifyBySessionId(final String principal, final byte[] sessionId) throws InterruptedException {
    try {
      final RegistrationServiceSession session = registrationServiceClient
          .getSession(sessionId, REGISTRATION_RPC_TIMEOUT)
          .get(VERIFICATION_TIMEOUT_SECONDS, TimeUnit.SECONDS)
          .orElseThrow(() -> new NotAuthorizedException("session not verified"));

      if (!MessageDigest.isEqual(principal.getBytes(), session.principal().getBytes())) {
        throw new BadRequestException("principal does not match session");
      }
      if (!session.verified()) {
        throw new NotAuthorizedException("session not verified");
      }
    } catch (final ExecutionException e) {

      if (e.getCause() instanceof StatusRuntimeException grpcRuntimeException) {
        if (grpcRuntimeException.getStatus().getCode() == Status.Code.INVALID_ARGUMENT) {
          throw new BadRequestException();
        }
      }

      logger.error("Registration service failure", e);
      throw new ServerErrorException(Response.Status.SERVICE_UNAVAILABLE);

    } catch (final CancellationException | TimeoutException e) {

      logger.error("Registration service failure", e);
      throw new ServerErrorException(Response.Status.SERVICE_UNAVAILABLE);
    }
  }

  private void verifyByRecoveryPassword(final ContainerRequestContext requestContext, final String principal, final byte[] recoveryPassword)
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
  }

}
