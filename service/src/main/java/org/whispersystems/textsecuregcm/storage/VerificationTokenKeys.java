/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import com.nimbusds.jose.jwk.JWKSet;
import org.whispersystems.textsecuregcm.registration.VerificationSession;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;

import java.time.Clock;

public class VerificationTokenKeys extends SerializedExpireableJsonDynamoStore<JWKSet> {

  public VerificationTokenKeys(final DynamoDbAsyncClient dynamoDbClient, final String tableName, final Clock clock) {
    super(dynamoDbClient, tableName, clock);
  }
}
