/*
 * Copyright 2023 Signal Messenger, LLC
 * Copyright 2025 Molly Instant Messenger
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import com.nimbusds.jose.jwk.JWKSet;

public class VerificationTokenKeysManager {

  private final VerificationTokenKeys tokenKeysStore;

  public VerificationTokenKeysManager(final VerificationTokenKeys tokenKeys) {
    this.tokenKeysStore = tokenKeys;
  }

  public CompletableFuture<Void> insert(final String uri, final JWKSet jwks) {
    return tokenKeysStore.insert(uri, jwks);
  }

  public CompletableFuture<Void> update(final String uri, final JWKSet jwks) {
    return tokenKeysStore.update(uri, jwks);
  }

  public CompletableFuture<Optional<JWKSet>> findForUri(final String uri) {
    return tokenKeysStore.findForKey(uri);
  }
}
