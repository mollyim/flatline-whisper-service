/*
 * Copyright 2025 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import java.util.concurrent.CompletableFuture;

/**
 * The DynamoDB recovery manager regenerates data for secondary tables in a disaster recovery scenario. In a disaster
 * recovery scenario, there is no guarantee that table backups will be consistent, and so we need to derive or update
 * some tables from a "core" data source to ensure consistency.
 */
public class DynamoDbRecoveryManager {

  private final Accounts accounts;
  private final PrincipalNameIdentifiers principalNameIdentifiers;

  public DynamoDbRecoveryManager(final Accounts accounts, final PrincipalNameIdentifiers principalNameIdentifiers) {
    this.accounts = accounts;
    this.principalNameIdentifiers = principalNameIdentifiers;
  }

  /**
   * Regenerates secondary data (i.e. uniqueness constraints) for a given account.
   *
   * @param account the account for which to regenerate secondary data
   *
   * @return a future that completes when secondary for the given account has been regenerated
   */
  public CompletableFuture<Void> regenerateData(final Account account) {
    return CompletableFuture.allOf(
        accounts.regenerateConstraints(account),
        principalNameIdentifiers.regeneratePhoneNumberIdentifierMappings(account));
  }
}
