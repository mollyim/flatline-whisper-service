/*
 * Copyright 2013-2021 Signal Messenger, LLC
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
