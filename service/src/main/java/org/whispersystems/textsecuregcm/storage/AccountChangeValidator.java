/*
 * Copyright 2013-2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import java.security.MessageDigest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


class AccountChangeValidator {

  private static final byte[] NO_HASH = new byte[32];

  private final boolean allowPrincipalChange;
  private final boolean allowUsernameHashChange;

  static final AccountChangeValidator GENERAL_CHANGE_VALIDATOR = new AccountChangeValidator(false, false);
  static final AccountChangeValidator PRINCIPAL_CHANGE_VALIDATOR = new AccountChangeValidator(true, false);
  static final AccountChangeValidator USERNAME_CHANGE_VALIDATOR = new AccountChangeValidator(false, true);

  private static final Logger logger = LoggerFactory.getLogger(AccountChangeValidator.class);

  AccountChangeValidator(final boolean allowPrincipalChange,
      final boolean allowUsernameHashChange) {

    this.allowPrincipalChange = allowPrincipalChange;
    this.allowUsernameHashChange = allowUsernameHashChange;
  }

  public void validateChange(final Account originalAccount, final Account updatedAccount) {
    if (!allowPrincipalChange) {
      assert updatedAccount.getPrincipal().equals(originalAccount.getPrincipal());

      if (!updatedAccount.getPrincipal().equals(originalAccount.getPrincipal())) {
        logger.error("Account principal changed via \"normal\" update; principals must be changed via changePrincipal method",
            new RuntimeException());
      }

      assert updatedAccount.getPrincipalNameIdentifier().equals(originalAccount.getPrincipalNameIdentifier());

      if (!updatedAccount.getPrincipalNameIdentifier().equals(originalAccount.getPrincipalNameIdentifier())) {
        logger.error(
            "Principal name identifier changed via \"normal\" update; PNIs must be changed via changePrincipal method",
            new RuntimeException());
      }
    }

    if (!allowUsernameHashChange) {
      final byte[] updatedAccountUsernameHash = updatedAccount.getUsernameHash().orElse(NO_HASH);
      final byte[] originalAccountUsernameHash = originalAccount.getUsernameHash().orElse(NO_HASH);

      boolean usernameUnchanged = MessageDigest.isEqual(updatedAccountUsernameHash, originalAccountUsernameHash);

      if (!usernameUnchanged) {
        logger.error("Username hash changed via \"normal\" update; username hashes must be changed via reserveUsernameHash and confirmUsernameHash methods",
            new RuntimeException());
      }
      assert usernameUnchanged;
    }
  }
}
