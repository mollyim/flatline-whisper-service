/*
 * Copyright 2013-2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.i18n.phonenumbers.PhoneNumberUtil;
import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.whispersystems.textsecuregcm.identity.IdentityType;
import org.whispersystems.textsecuregcm.storage.DynamoDbExtensionSchema.Tables;
import org.whispersystems.textsecuregcm.util.CompletableFutureTestUtil;
import software.amazon.awssdk.services.dynamodb.model.TransactionCanceledException;

class PhoneNumberIdentifiersTest {

  @RegisterExtension
  static DynamoDbExtension DYNAMO_DB_EXTENSION = new DynamoDbExtension(Tables.PNI);

  private PrincipalNameIdentifiers principalNameIdentifiers;

  @BeforeEach
  void setUp() {
    principalNameIdentifiers = new PrincipalNameIdentifiers(DYNAMO_DB_EXTENSION.getDynamoDbAsyncClient(),
        Tables.PNI.tableName());
  }

  @Test
  void getPhoneNumberIdentifier() {
    final String number = "+18005551234";
    final String differentNumber = "+18005556789";

    final UUID firstPni = principalNameIdentifiers.getPrincipalNameIdentifier(number).join();
    final UUID secondPni = principalNameIdentifiers.getPrincipalNameIdentifier(number).join();

    assertEquals(firstPni, secondPni);
    assertNotEquals(firstPni, principalNameIdentifiers.getPrincipalNameIdentifier(differentNumber).join());
  }

  @Test
  void generatePhoneNumberIdentifier() {
    final List<String> numbers = List.of("+18005551234", "+18005556789");
    // Should set both PNIs to a new random PNI
    final UUID pni = principalNameIdentifiers.setPniIfRequired(numbers.getFirst(), numbers, Collections.emptyMap()).join();

    assertEquals(pni, principalNameIdentifiers.getPrincipalNameIdentifier(numbers.getFirst()).join());
    assertEquals(pni, principalNameIdentifiers.getPrincipalNameIdentifier(numbers.getLast()).join());
  }

  @Test
  void generatePhoneNumberIdentifierOneFormExists() {
    final String firstNumber = "+18005551234";
    final String secondNumber = "+18005556789";
    final String thirdNumber = "+1800555456";
    final List<String> allNumbers = List.of(firstNumber, secondNumber, thirdNumber);

    // Set one member of the "same" numbers to a new PNI
    final UUID pni = principalNameIdentifiers.getPrincipalNameIdentifier(secondNumber).join();

    final Map<String, UUID> existingAssociations = principalNameIdentifiers.fetchPrincipals(allNumbers).join();
    assertEquals(Map.of(secondNumber, pni), existingAssociations);

    assertEquals(pni, principalNameIdentifiers.setPniIfRequired(firstNumber, allNumbers, existingAssociations).join());

    for (String number : allNumbers) {
      assertEquals(pni, principalNameIdentifiers.getPrincipalNameIdentifier(number).join());
    }
  }

  @Test
  void getPhoneNumberIdentifierExistingMapping() {
    final String newFormatBeninE164 = PhoneNumberUtil.getInstance()
        .format(PhoneNumberUtil.getInstance().getExampleNumber("BJ"), PhoneNumberUtil.PhoneNumberFormat.E164);

    final String oldFormatBeninE164 = newFormatBeninE164.replaceFirst("01", "");
    final UUID oldFormatPni = principalNameIdentifiers.getPrincipalNameIdentifier(oldFormatBeninE164).join();
    final UUID newFormatPni = principalNameIdentifiers.getPrincipalNameIdentifier(newFormatBeninE164).join();
    assertEquals(oldFormatPni, newFormatPni);
  }

  @Test
  void conflictingExistingPnis() {
    final String firstNumber = "+18005551234";
    final String secondNumber = "+18005556789";

    final UUID firstPni = principalNameIdentifiers.getPrincipalNameIdentifier(firstNumber).join();
    final UUID secondPni = principalNameIdentifiers.getPrincipalNameIdentifier(secondNumber).join();
    assertNotEquals(firstPni, secondPni);

    assertEquals(
        firstPni,
        principalNameIdentifiers.setPniIfRequired(
            firstNumber, List.of(firstNumber, secondNumber),
            principalNameIdentifiers.fetchPrincipals(List.of(firstNumber, secondNumber)).join()).join());
    assertEquals(
        secondPni,
        principalNameIdentifiers.setPniIfRequired(
            secondNumber, List.of(secondNumber, firstNumber),
            principalNameIdentifiers.fetchPrincipals(List.of(firstNumber, secondNumber)).join()).join());
  }

  @Test
  void conflictOnOriginalNumber() {
    final List<String> numbers = List.of("+18005551234", "+18005556789");
    // Stale view of database where both numbers have no PNI
    final Map<String, UUID> existingAssociations = Collections.emptyMap();

    // Both numbers have different PNIs
    final UUID pni1 = principalNameIdentifiers.getPrincipalNameIdentifier(numbers.getFirst()).join();
    final UUID pni2 = principalNameIdentifiers.getPrincipalNameIdentifier(numbers.getLast()).join();
    assertNotEquals(pni1, pni2);

    // Should conflict and find that we now have a PNI
    assertEquals(pni1, principalNameIdentifiers.setPniIfRequired(numbers.getFirst(), numbers, existingAssociations).join());
  }

  @Test
  void conflictOnAlternateNumber() {
    final List<String> numbers = List.of("+18005551234", "+18005556789");
    // Stale view of database where both numbers have no PNI
    final Map<String, UUID> existingAssociations = Collections.emptyMap();

    // the alternate number has a PNI added
    principalNameIdentifiers.getPrincipalNameIdentifier(numbers.getLast()).join();

    // Should conflict and fail
    CompletableFutureTestUtil.assertFailsWithCause(
        TransactionCanceledException.class,
        principalNameIdentifiers.setPniIfRequired(numbers.getFirst(), numbers, existingAssociations));
  }

  @Test
  void multipleAssociations() {
    final List<String> numbers = List.of("+18005550000", "+18005551111", "+18005552222", "+18005553333", "+1800555444");

    // Set pni1={number1, number2}, pni2={number3}, number0 and number 4 unset
    final UUID pni1 = principalNameIdentifiers.setPniIfRequired(numbers.get(1), numbers.subList(1, 3),
        Collections.emptyMap()).join();
    final UUID pni2 = principalNameIdentifiers.setPniIfRequired(numbers.get(3), List.of(numbers.get(3)),
        Collections.emptyMap()).join();

    final Map<String, UUID> existingAssociations = principalNameIdentifiers.fetchPrincipals(numbers).join();
    assertEquals(existingAssociations, Map.of(numbers.get(1), pni1, numbers.get(2), pni1, numbers.get(3), pni2));

    // The unmapped phone numbers should map to the arbitrarily selected PNI (which is selected based on the order
    // of the numbers)
    assertEquals(pni1, principalNameIdentifiers.setPniIfRequired(numbers.get(0), numbers, existingAssociations).join());
    assertEquals(pni1, principalNameIdentifiers.getPrincipalNameIdentifier(numbers.get(0)).join());
    assertEquals(pni1, principalNameIdentifiers.getPrincipalNameIdentifier(numbers.get(4)).join());
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
  void getPhoneNumber() {
    final String number = "+18005551234";

    assertTrue(principalNameIdentifiers.getPrincipal(UUID.randomUUID()).join().isEmpty());

    final UUID pni = principalNameIdentifiers.getPrincipalNameIdentifier(number).join();
    assertEquals(List.of(number), principalNameIdentifiers.getPrincipal(pni).join());
  }

  @Test
  void regeneratePhoneNumberIdentifierMappings() {
    // libphonenumber 8.13.50 and on generate new-format numbers for Benin
    final String newFormatBeninE164 = PhoneNumberUtil.getInstance()
        .format(PhoneNumberUtil.getInstance().getExampleNumber("BJ"), PhoneNumberUtil.PhoneNumberFormat.E164);
    final String oldFormatBeninE164 = newFormatBeninE164.replaceFirst("01", "");

    final UUID phoneNumberIdentifier = UUID.randomUUID();

    final Account account = mock(Account.class);
    when(account.getPrincipal()).thenReturn(newFormatBeninE164);
    when(account.getIdentifier(IdentityType.PNI)).thenReturn(phoneNumberIdentifier);

    principalNameIdentifiers.regeneratePhoneNumberIdentifierMappings(account).join();

    assertEquals(phoneNumberIdentifier, principalNameIdentifiers.getPrincipalNameIdentifier(newFormatBeninE164).join());
    assertEquals(phoneNumberIdentifier, principalNameIdentifiers.getPrincipalNameIdentifier(oldFormatBeninE164).join());
    assertEquals(Set.of(newFormatBeninE164, oldFormatBeninE164),
        new HashSet<>(principalNameIdentifiers.getPrincipal(phoneNumberIdentifier).join()));
  }
}
