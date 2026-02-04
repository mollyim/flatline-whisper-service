/*
 * Copyright 2025 Molly Instant Messenger
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.util;

public class InvalidPrincipalException extends Exception {

  public InvalidPrincipalException() {
    super();
  }

  public InvalidPrincipalException(final Throwable cause) {
    super(cause);
  }

  public InvalidPrincipalException(final String cause) {
    super(cause);
  }
}
