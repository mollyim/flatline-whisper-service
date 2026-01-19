/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.entities;

import static org.apache.commons.lang3.StringUtils.isNotBlank;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotEmpty;
import jakarta.ws.rs.ClientErrorException;
import java.util.Base64;
import org.apache.http.HttpStatus;
import org.jetbrains.annotations.NotNull;
import org.whispersystems.textsecuregcm.storage.Subject;


public class PrincipalVerificationDetails {
  public enum VerificationType {
    SESSION,
    RECOVERY_PASSWORD
  }

  private final VerificationType verificationType;
  private final String providerId;
  private final String subject;
  private final String principal;

  public PrincipalVerificationDetails(
      VerificationType verificationType,
      String providerId,
      String subject,
      String principal) {
    this.verificationType = verificationType;
    this.providerId = providerId;
    this.subject = subject;
    this.principal = principal;
  }

  // FLT(uoemai): This constructor is used when the principal verification is not associated with
  //              a verification provider nor an identity subject, such as with a recovery password.
  public PrincipalVerificationDetails(
      VerificationType verificationType,
      String principal) {
    this.verificationType = verificationType;
    this.providerId = null;
    this.subject = null;
    this.principal = principal;
  }

  public VerificationType verificationType() {
    return verificationType;
  }
  public String providerId() {
    return providerId;
  }
  public String subject() {
    return subject;
  }
  public String principal() {
    return principal;
  }

  public Subject toSubject() {
    return new Subject(providerId, subject);
  }
}
