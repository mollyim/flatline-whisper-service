/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.storage;

import org.jetbrains.annotations.NotNull;

public record Subject(String providerId, String subject) {
  public static Subject fromString(String s) {
    if (s.isBlank()) throw new IllegalArgumentException("subject string is blank");
    // FLT(uoemai): Splitting with a limit of two will ensure that the subject string is allowed to contain colons.
    //              The provider identifier is enforced to not contain colons when validating the configuration.
    String[] parts = s.split(":", 2);
    if (parts.length != 2) throw new IllegalArgumentException("subject string format is invalid");
    String providerId = parts[0];
    String subject = parts[1];
    return new Subject(providerId, subject);
  }

  @Override
  public @NotNull String toString() {
    if (providerId.contains(":")) throw new IllegalArgumentException("providerId contains forbidden character");
    return providerId + ":" + subject;
  }
}

