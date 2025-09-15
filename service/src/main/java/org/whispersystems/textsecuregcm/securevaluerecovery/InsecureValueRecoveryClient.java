/*
 * Copyright 2023 Signal Messenger, LLC
 * Copyright 2025 Molly Instant Messenger
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.securevaluerecovery;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public class InsecureValueRecoveryClient implements ValueRecoveryClient {
  public InsecureValueRecoveryClient(){};

  public CompletableFuture<Void> removeData(final UUID accountUuid) {
    return null;
  }
  public CompletableFuture<Void> removeData(final String userIdentifier) {
    return null;
  }
}
