/*
 * Copyright 2013-2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.whispersystems.textsecuregcm.storage.DynamoDbExtensionSchema.Tables;
import org.whispersystems.textsecuregcm.util.CompletableFutureTestUtil;
import software.amazon.awssdk.services.dynamodb.model.TransactionCanceledException;

class PrincipalNameIdentifiersTest {

  @RegisterExtension
  static DynamoDbExtension DYNAMO_DB_EXTENSION = new DynamoDbExtension(Tables.PNI);

  private PrincipalNameIdentifiers principalNameIdentifiers;

  @BeforeEach
  void setUp() {
    principalNameIdentifiers = new PrincipalNameIdentifiers(DYNAMO_DB_EXTENSION.getDynamoDbAsyncClient(),
        Tables.PNI.tableName());
  }

  @Test
  void getPrincipalNameIdentifier() {
    final String principal = "user.account@example.com";
    final String differentPrincipal = "different.user.account@example.com";

    final UUID firstPni = principalNameIdentifiers.getPrincipalNameIdentifier(principal).join();
    final UUID secondPni = principalNameIdentifiers.getPrincipalNameIdentifier(principal).join();

    assertEquals(firstPni, secondPni);
    assertNotEquals(firstPni, principalNameIdentifiers.getPrincipalNameIdentifier(differentPrincipal).join());
  }

  @Test
  void generatePrincipalNameIdentifier() {
    final List<String> principals = List.of("user.account@example.com", "different.user.account@example.com");
    // Should set both PNIs to a new random PNI
    final UUID pni = principalNameIdentifiers.setPniIfRequired(principals.getFirst(), principals, Collections.emptyMap()).join();

    assertEquals(pni, principalNameIdentifiers.getPrincipalNameIdentifier(principals.getFirst()).join());
    assertEquals(pni, principalNameIdentifiers.getPrincipalNameIdentifier(principals.getLast()).join());
  }

  @Test
  void generatePrincipalNameIdentifierOneFormExists() {
    final String firstPrincipal = "user.account@example.com";
    final String secondPrincipal = " user.account.2@example.com";
    final String thirdPrincipal = "   user.account.3@example.com   ";
    final List<String> allPrincipals = List.of(firstPrincipal, secondPrincipal, thirdPrincipal);

    // Set one member of the "same" principal to a new PNI
    final UUID pni = principalNameIdentifiers.getPrincipalNameIdentifier(secondPrincipal).join();

    final Map<String, UUID> existingAssociations = principalNameIdentifiers.fetchPrincipals(allPrincipals).join();
    assertEquals(Map.of(secondPrincipal, pni), existingAssociations);

    assertEquals(pni, principalNameIdentifiers.setPniIfRequired(firstPrincipal, allPrincipals, existingAssociations).join());

    for (String principal : allPrincipals) {
      assertEquals(pni, principalNameIdentifiers.getPrincipalNameIdentifier(principal).join());
    }
  }

  @Test
  void getPrincipalNameIdentifierExistingMapping() {
    // FLT(uoemai): In Flatline, there are currently no two different principals that should have the same PNI.
    //              Previously, this would be the case for functionally equivalent phone numbers.
    //              This test is kept to document this change and keep the option open for the future.
  }

  @Test
  void conflictingExistingPnis() {
    final String firstPrincipal = "user.account.1@example.com";
    final String secondPrincipal = "user.account.2@example.com";

    final UUID firstPni = principalNameIdentifiers.getPrincipalNameIdentifier(firstPrincipal).join();
    final UUID secondPni = principalNameIdentifiers.getPrincipalNameIdentifier(secondPrincipal).join();
    assertNotEquals(firstPni, secondPni);

    assertEquals(
        firstPni,
        principalNameIdentifiers.setPniIfRequired(
            firstPrincipal, List.of(firstPrincipal, secondPrincipal),
            principalNameIdentifiers.fetchPrincipals(List.of(firstPrincipal, secondPrincipal)).join()).join());
    assertEquals(
        secondPni,
        principalNameIdentifiers.setPniIfRequired(
            secondPrincipal, List.of(secondPrincipal, firstPrincipal),
            principalNameIdentifiers.fetchPrincipals(List.of(firstPrincipal, secondPrincipal)).join()).join());
  }

  @Test
  void conflictOnOriginalPrincipal() {
    final List<String> principals = List.of("user.account.1@example.com", "user.account.2@example.com");
    // Stale view of database where both principals have no PNI
    final Map<String, UUID> existingAssociations = Collections.emptyMap();

    // Both principals have different PNIs
    final UUID pni1 = principalNameIdentifiers.getPrincipalNameIdentifier(principals.getFirst()).join();
    final UUID pni2 = principalNameIdentifiers.getPrincipalNameIdentifier(principals.getLast()).join();
    assertNotEquals(pni1, pni2);

    // Should conflict and find that we now have a PNI
    assertEquals(pni1, principalNameIdentifiers.setPniIfRequired(principals.getFirst(), principals, existingAssociations).join());
  }

  @Test
  void conflictOnAlternatePrincipal() {
    final List<String> principals = List.of("+18005551234", "+18005556789");
    // Stale view of database where both numbers have no PNI
    final Map<String, UUID> existingAssociations = Collections.emptyMap();

    // the alternate principal has a PNI added
    principalNameIdentifiers.getPrincipalNameIdentifier(principals.getLast()).join();

    // Should conflict and fail
    CompletableFutureTestUtil.assertFailsWithCause(
        TransactionCanceledException.class,
        principalNameIdentifiers.setPniIfRequired(principals.getFirst(), principals, existingAssociations));
  }

  @Test
  void multipleAssociations() {
    final List<String> principals = List.of("user.account.1@example.com", "user.account.2@example.com",
        "user.account.3@example.com", "user.account.4@example.com", "user.account.5@example.com");

    // Set pni1={principal1, principal2}, pni2={principal3}, principal0 and principal4 unset
    final UUID pni1 = principalNameIdentifiers.setPniIfRequired(principals.get(1), principals.subList(1, 3),
        Collections.emptyMap()).join();
    final UUID pni2 = principalNameIdentifiers.setPniIfRequired(principals.get(3), List.of(principals.get(3)),
        Collections.emptyMap()).join();

    final Map<String, UUID> existingAssociations = principalNameIdentifiers.fetchPrincipals(principals).join();
    assertEquals(existingAssociations, Map.of(principals.get(1), pni1, principals.get(2), pni1, principals.get(3), pni2));

    // The unmapped principals should map to the arbitrarily selected PNI (which is selected based on the order
    // of the principals)
    assertEquals(pni1, principalNameIdentifiers.setPniIfRequired(principals.get(0), principals, existingAssociations).join());
    assertEquals(pni1, principalNameIdentifiers.getPrincipalNameIdentifier(principals.get(0)).join());
    assertEquals(pni1, principalNameIdentifiers.getPrincipalNameIdentifier(principals.get(4)).join());
  }

  private static class FailN implements Supplier<CompletableFuture<Integer>> {
    final AtomicInteger numFails;

    FailN(final int numFails) {
      this.numFails = new AtomicInteger(numFails);
    }

    @Override
    public CompletableFuture<Integer> get() {
      if (numFails.getAndDecrement() == 0) {
        return CompletableFuture.completedFuture(7);
      }
      return CompletableFuture.failedFuture(new IOException("test"));
    }
  }

  @Test
  void testRetry() {
    assertEquals(7, PrincipalNameIdentifiers.retry(10, IOException.class, new FailN(9)).join());

    CompletableFutureTestUtil.assertFailsWithCause(
        IOException.class,
        PrincipalNameIdentifiers.retry(10, IOException.class, new FailN(10)));

    CompletableFutureTestUtil.assertFailsWithCause(
        IOException.class,
        PrincipalNameIdentifiers.retry(10, RuntimeException.class, new FailN(1)));
  }

  @Test
  void getPrincipal() {
    final String principal = "user.account@example.com";

    assertTrue(principalNameIdentifiers.getPrincipal(UUID.randomUUID()).join().isEmpty());

    final UUID pni = principalNameIdentifiers.getPrincipalNameIdentifier(principal).join();
    assertEquals(List.of(principal), principalNameIdentifiers.getPrincipal(pni).join());
  }

  @Test
  void regeneratePrincipalNameIdentifierMappings() {
    // FLT(uoemai): In Flatline, there are currently no two different principals that should have the same PNI.
    //              Previously, this would be the case for functionally equivalent phone numbers.
    //              This test is kept to document this change and keep the option open for the future.
  }
}
