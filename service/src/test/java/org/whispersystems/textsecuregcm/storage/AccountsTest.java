/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.signal.libsignal.zkgroup.backups.BackupCredentialType;
import org.whispersystems.textsecuregcm.auth.UnidentifiedAccessUtil;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicConfiguration;
import org.whispersystems.textsecuregcm.entities.PrincipalVerificationDetails;
import org.whispersystems.textsecuregcm.identity.IdentityType;
import org.whispersystems.textsecuregcm.storage.DynamoDbExtensionSchema.Tables;
import org.whispersystems.textsecuregcm.tests.util.AccountsHelper;
import org.whispersystems.textsecuregcm.tests.util.DevicesHelper;
import org.whispersystems.textsecuregcm.util.AttributeValues;
import org.whispersystems.textsecuregcm.util.CompletableFutureTestUtil;
import org.whispersystems.textsecuregcm.util.SystemMapper;
import org.whispersystems.textsecuregcm.util.TestClock;
import org.whispersystems.textsecuregcm.util.TestRandomUtil;
import reactor.core.scheduler.Schedulers;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.CancellationReason;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.Put;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.ReturnValuesOnConditionCheckFailure;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsResponse;
import software.amazon.awssdk.services.dynamodb.model.TransactionCanceledException;
import software.amazon.awssdk.services.dynamodb.model.TransactionConflictException;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;

@Timeout(value = 10, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class AccountsTest {

  private static final byte DEVICE_ID_1 = 1;
  private static final byte DEVICE_ID_2 = 2;

  private static final String BASE_64_URL_USERNAME_HASH_1 = "9p6Tip7BFefFOJzv4kv4GyXEYsBVfk_WbjNejdlOvQE";
  private static final String BASE_64_URL_USERNAME_HASH_2 = "NLUom-CHwtemcdvOTTXdmXmzRIV7F05leS8lwkVK_vc";
  private static final String BASE_64_URL_ENCRYPTED_USERNAME_1 = "md1votbj9r794DsqTNrBqA";
  private static final String BASE_64_URL_ENCRYPTED_USERNAME_2 = "9hrqVLy59bzgPse-S9NUsA";
  private static final byte[] USERNAME_HASH_1 = Base64.getUrlDecoder().decode(BASE_64_URL_USERNAME_HASH_1);
  private static final byte[] USERNAME_HASH_2 = Base64.getUrlDecoder().decode(BASE_64_URL_USERNAME_HASH_2);
  private static final byte[] ENCRYPTED_USERNAME_1 = Base64.getUrlDecoder().decode(BASE_64_URL_ENCRYPTED_USERNAME_1);
  private static final byte[] ENCRYPTED_USERNAME_2 = Base64.getUrlDecoder().decode(BASE_64_URL_ENCRYPTED_USERNAME_2);

  private static final AtomicInteger ACCOUNT_COUNTER = new AtomicInteger(1);


  @RegisterExtension
  static final DynamoDbExtension DYNAMO_DB_EXTENSION = new DynamoDbExtension(
      Tables.ACCOUNTS,
      Tables.PRINCIPALS,
      Tables.PNI_ASSIGNMENTS,
      Tables.USERNAMES,
      Tables.DELETED_ACCOUNTS,
      Tables.USED_LINK_DEVICE_TOKENS,

      // This is an unrelated table used to test "tag-along" transactional updates
      Tables.CLIENT_RELEASES);

  private final TestClock clock = TestClock.pinned(Instant.EPOCH);
  private Accounts accounts;

  private record UsernameConstraint(UUID accountIdentifier, boolean confirmed, Optional<Instant> expiration) {
  }

  @BeforeEach
  void setupAccountsDao() {

    @SuppressWarnings("unchecked") DynamicConfigurationManager<DynamicConfiguration> dynamicConfigurationManager =
        mock(DynamicConfigurationManager.class);

    when(dynamicConfigurationManager.getConfiguration()).thenReturn(new DynamicConfiguration());

    clock.pin(Instant.EPOCH);
    accounts = new Accounts(
        clock,
        DYNAMO_DB_EXTENSION.getDynamoDbClient(),
        DYNAMO_DB_EXTENSION.getDynamoDbAsyncClient(),
        Tables.ACCOUNTS.tableName(),
        Tables.PRINCIPALS.tableName(),
        Tables.PNI_ASSIGNMENTS.tableName(),
        Tables.SUBJECTS.tableName(),
        Tables.USERNAMES.tableName(),
        Tables.DELETED_ACCOUNTS.tableName(),
        Tables.USED_LINK_DEVICE_TOKENS.tableName());
  }

  @Test
  public void testStoreAndLookupUsernameLink() {
    final Account account = nextRandomAccount();
    account.setUsernameHash(TestRandomUtil.nextBytes(16));
    createAccount(account);

    final BiConsumer<Optional<Account>, byte[]> validator = (maybeAccount, expectedEncryptedUsername) -> {
      assertTrue(maybeAccount.isPresent());
      assertTrue(maybeAccount.get().getEncryptedUsername().isPresent());
      assertEquals(account.getUuid(), maybeAccount.get().getUuid());
      assertArrayEquals(expectedEncryptedUsername, maybeAccount.get().getEncryptedUsername().get());
    };

    // creating a username link, storing it, checking that it can be looked up
    final UUID linkHandle1 = UUID.randomUUID();
    final byte[] encruptedUsername1 = TestRandomUtil.nextBytes(32);
    account.setUsernameLinkDetails(linkHandle1, encruptedUsername1);
    accounts.update(account);
    validator.accept(accounts.getByUsernameLinkHandle(linkHandle1).join(), encruptedUsername1);

    // updating username link, storing new one, checking that it can be looked up, checking that old one can't be looked up
    final UUID linkHandle2 = UUID.randomUUID();
    final byte[] encruptedUsername2 = TestRandomUtil.nextBytes(32);
    account.setUsernameLinkDetails(linkHandle2, encruptedUsername2);
    accounts.update(account);
    validator.accept(accounts.getByUsernameLinkHandle(linkHandle2).join(), encruptedUsername2);
    assertTrue(accounts.getByUsernameLinkHandle(linkHandle1).join().isEmpty());

    // deleting username link, checking it can't be looked up by either handle
    account.setUsernameLinkDetails(null, null);
    accounts.update(account);
    assertTrue(accounts.getByUsernameLinkHandle(linkHandle1).join().isEmpty());
    assertTrue(accounts.getByUsernameLinkHandle(linkHandle2).join().isEmpty());
  }

  @Test
  void testStore() {
    Device device = generateDevice(DEVICE_ID_1);
    Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID(), List.of(device));

    boolean freshUser = createAccount(account);

    assertThat(freshUser).isTrue();
    verifyStoredState("user.account@example.com", account.getUuid(), account.getPrincipalNameIdentifier(), null, account, true);

    assertPrincipalConstraintExists("user.account@example.com", account.getUuid());
    assertPrincipalNameIdentifierConstraintExists(account.getPrincipalNameIdentifier(), account.getUuid());

    freshUser = createAccount(account);
    assertThat(freshUser).isTrue();
    verifyStoredState("user.account@example.com", account.getUuid(), account.getPrincipalNameIdentifier(), null, account, true);

    assertPrincipalConstraintExists("user.account@example.com", account.getUuid());
    assertPrincipalNameIdentifierConstraintExists(account.getPrincipalNameIdentifier(), account.getUuid());
  }

  @Test
  void testStoreRecentlyDeleted() {
    final UUID originalUuid = UUID.randomUUID();

    Device device = generateDevice(DEVICE_ID_1);
    Account account = generateAccount("user.account@example.com", originalUuid, UUID.randomUUID(), List.of(device));

    boolean freshUser = createAccount(account);

    assertThat(freshUser).isTrue();
    verifyStoredState("user.account@example.com", account.getUuid(), account.getPrincipalNameIdentifier(), null, account, true);

    assertPrincipalConstraintExists("user.account@example.com", account.getUuid());
    assertPrincipalNameIdentifierConstraintExists(account.getPrincipalNameIdentifier(), account.getUuid());

    accounts.delete(originalUuid, Collections.emptyList()).join();
    assertThat(accounts.findRecentlyDeletedAccountIdentifier(account.getPrincipalNameIdentifier())).hasValue(originalUuid);

    freshUser = createAccount(account);
    assertThat(freshUser).isTrue();
    verifyStoredState("user.account@example.com", account.getUuid(), account.getPrincipalNameIdentifier(), null, account, true);

    assertPrincipalConstraintExists("user.account@example.com", account.getUuid());
    assertPrincipalNameIdentifierConstraintExists(account.getPrincipalNameIdentifier(), account.getUuid());

    assertThat(accounts.findRecentlyDeletedAccountIdentifier(account.getPrincipalNameIdentifier())).isEmpty();
  }

  @Test
  void testStoreMulti() {
    final List<Device> devices = List.of(generateDevice(DEVICE_ID_1), generateDevice(DEVICE_ID_2));
    final Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID(), devices);

    createAccount(account);

    verifyStoredState("user.account@example.com", account.getUuid(), account.getPrincipalNameIdentifier(), null, account, true);

    assertPrincipalConstraintExists("user.account@example.com", account.getUuid());
    assertPrincipalNameIdentifierConstraintExists(account.getPrincipalNameIdentifier(), account.getUuid());
  }

  @Test
  void testStoreAciCollisionFails() {
    Device device = generateDevice(DEVICE_ID_1);
    Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID(), List.of(device));

    boolean freshUser = createAccount(account);

    assertThat(freshUser).isTrue();
    verifyStoredState("user.account@example.com", account.getUuid(), account.getPrincipalNameIdentifier(), null, account, true);

    assertPrincipalConstraintExists("user.account@example.com", account.getUuid());
    assertPrincipalNameIdentifierConstraintExists(account.getPrincipalNameIdentifier(), account.getUuid());

    account.setPrincipal("different.user.account@example.com", UUID.randomUUID());
    assertThrows(IllegalArgumentException.class, () -> createAccount(account),
        "Reusing ACI with different PNI should fail");
  }

  @Test
  void testStorePniCollisionFails() {
    Device device1 = generateDevice(DEVICE_ID_1);
    Account account1 = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID(), List.of(device1));

    boolean freshUser = createAccount(account1);

    assertThat(freshUser).isTrue();
    verifyStoredState("user.account@example.com", account1.getUuid(), account1.getPrincipalNameIdentifier(), null, account1, true);

    assertPrincipalConstraintExists("user.account@example.com", account1.getUuid());
    assertPrincipalNameIdentifierConstraintExists(account1.getPrincipalNameIdentifier(), account1.getUuid());

    Device device2 = generateDevice(DEVICE_ID_1);
    Account account2 = generateAccount("user.account@example.com", UUID.randomUUID(), account1.getPrincipalNameIdentifier(),
        List.of(device2));

    assertThrows(AccountAlreadyExistsException.class, () -> accounts.create(account2,
            new PrincipalVerificationDetails(PrincipalVerificationDetails.VerificationType.SESSION,
                "provider", "subject", "user.account@example.com"), Collections.emptyList()),
        "New ACI with same PNI should fail");
  }

  @Test
  void testRetrieve() {
    final List<Device> devicesFirst = List.of(generateDevice(DEVICE_ID_1), generateDevice(DEVICE_ID_2));

    UUID uuidFirst = UUID.randomUUID();
    UUID pniFirst = UUID.randomUUID();
    Account accountFirst = generateAccount("user.account1@example.com", uuidFirst, pniFirst, devicesFirst);

    final List<Device> devicesSecond = List.of(generateDevice(DEVICE_ID_1), generateDevice(DEVICE_ID_2));

    UUID uuidSecond = UUID.randomUUID();
    UUID pniSecond = UUID.randomUUID();
    Account accountSecond = generateAccount("user.account2@example.com", uuidSecond, pniSecond, devicesSecond);

    createAccount(accountFirst);
    createAccount(accountSecond);

    Optional<Account> retrievedFirst = accounts.getByPrincipal("user.account1@example.com");
    Optional<Account> retrievedSecond = accounts.getByPrincipal("user.account2@example.com");

    assertThat(retrievedFirst.isPresent()).isTrue();
    assertThat(retrievedSecond.isPresent()).isTrue();

    verifyStoredState("user.account1@example.com", uuidFirst, pniFirst, null, retrievedFirst.get(), accountFirst);
    verifyStoredState("user.account2@example.com", uuidSecond, pniSecond, null, retrievedSecond.get(), accountSecond);

    retrievedFirst = accounts.getByAccountIdentifier(uuidFirst);
    retrievedSecond = accounts.getByAccountIdentifier(uuidSecond);

    assertThat(retrievedFirst.isPresent()).isTrue();
    assertThat(retrievedSecond.isPresent()).isTrue();

    verifyStoredState("user.account1@example.com", uuidFirst, pniFirst, null, retrievedFirst.get(), accountFirst);
    verifyStoredState("user.account2@example.com", uuidSecond, pniSecond, null, retrievedSecond.get(), accountSecond);

    retrievedFirst = accounts.getByPrincipalNameIdentifier(pniFirst);
    retrievedSecond = accounts.getByPrincipalNameIdentifier(pniSecond);

    assertThat(retrievedFirst.isPresent()).isTrue();
    assertThat(retrievedSecond.isPresent()).isTrue();

    verifyStoredState("user.account1@example.com", uuidFirst, pniFirst, null, retrievedFirst.get(), accountFirst);
    verifyStoredState("user.account2@example.com", uuidSecond, pniSecond, null, retrievedSecond.get(), accountSecond);
  }

  @Test
  void testRetrieveNoPni() throws JsonProcessingException {
    final List<Device> devices = List.of(generateDevice(DEVICE_ID_1), generateDevice(DEVICE_ID_2));
    final UUID uuid = UUID.randomUUID();
    final Account account = generateAccount("user.account@example.com", uuid, null, devices);

    // Accounts#create enforces that newly-created accounts have a PNI, so we need to make a bit of an end-run around it
    // to simulate an existing account with no PNI.
    {
      final TransactWriteItem principalConstraintPut = TransactWriteItem.builder()
          .put(
              Put.builder()
                  .tableName(Tables.PRINCIPALS.tableName())
                  .item(Map.of(
                      Accounts.ATTR_ACCOUNT_PRINCIPAL, AttributeValues.fromString(account.getPrincipal()),
                      Accounts.KEY_ACCOUNT_UUID, AttributeValues.fromUUID(account.getUuid())))
                  .conditionExpression(
                      "attribute_not_exists(#principal) OR (attribute_exists(#principal) AND #uuid = :uuid)")
                  .expressionAttributeNames(
                      Map.of("#uuid", Accounts.KEY_ACCOUNT_UUID,
                          "#principal", Accounts.ATTR_ACCOUNT_PRINCIPAL))
                  .expressionAttributeValues(
                      Map.of(":uuid", AttributeValues.fromUUID(account.getUuid())))
                  .returnValuesOnConditionCheckFailure(ReturnValuesOnConditionCheckFailure.ALL_OLD)
                  .build())
          .build();

      final TransactWriteItem accountPut = TransactWriteItem.builder()
          .put(Put.builder()
              .tableName(Tables.ACCOUNTS.tableName())
              .conditionExpression("attribute_not_exists(#principal) OR #principal = :principal")
              .expressionAttributeNames(Map.of("#principal", Accounts.ATTR_ACCOUNT_PRINCIPAL))
              .expressionAttributeValues(Map.of(":principal", AttributeValues.fromString(account.getPrincipal())))
              .item(Map.of(
                  Accounts.KEY_ACCOUNT_UUID, AttributeValues.fromUUID(uuid),
                  Accounts.ATTR_ACCOUNT_PRINCIPAL, AttributeValues.fromString(account.getPrincipal()),
                  Accounts.ATTR_ACCOUNT_DATA, AttributeValues.fromByteArray(SystemMapper.jsonMapper().writeValueAsBytes(account)),
                  Accounts.ATTR_VERSION, AttributeValues.fromInt(account.getVersion()),
                  Accounts.ATTR_CANONICALLY_DISCOVERABLE, AttributeValues.fromBool(account.isDiscoverableByPrincipal())))
              .build())
          .build();

      DYNAMO_DB_EXTENSION.getDynamoDbClient().transactWriteItems(TransactWriteItemsRequest.builder()
          .transactItems(principalConstraintPut, accountPut)
          .build());
    }

    Optional<Account> retrieved = accounts.getByPrincipal("user.account@example.com");

    assertThat(retrieved.isPresent()).isTrue();
    verifyStoredState("user.account@example.com", uuid, null, null, retrieved.get(), account);

    retrieved = accounts.getByAccountIdentifier(uuid);

    assertThat(retrieved.isPresent()).isTrue();
    verifyStoredState("user.account@example.com", uuid, null, null, retrieved.get(), account);
  }

  // State before the account is re-registered
  enum UsernameStatus {
    NONE,
    RESERVED,
    RESERVED_WITH_SAVED_LINK,
    CONFIRMED
  }

  @ParameterizedTest
  @EnumSource(UsernameStatus.class)
  void reclaimAccountWithNoUsername(UsernameStatus usernameStatus) {
    Device device = generateDevice(DEVICE_ID_1);
    UUID firstUuid = UUID.randomUUID();
    UUID firstPni = UUID.randomUUID();
    Account account = generateAccount("user.account@example.com", firstUuid, firstPni, List.of(device));
    createAccount(account);

    final byte[] usernameHash = TestRandomUtil.nextBytes(32);
    final byte[] encryptedUsername = TestRandomUtil.nextBytes(32);
    switch (usernameStatus) {
      case NONE:
        break;
      case RESERVED:
        accounts.reserveUsernameHash(account, TestRandomUtil.nextBytes(32), Duration.ofMinutes(1)).join();
        break;
      case RESERVED_WITH_SAVED_LINK:
        // give the account a username
        accounts.reserveUsernameHash(account, usernameHash, Duration.ofMinutes(1)).join();
        accounts.confirmUsernameHash(account, usernameHash, encryptedUsername).join();

        // simulate a partially-completed re-reg: we give the account a reclaimable username, but we'll try
        // re-registering again later in the test case
        account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID(), List.of(generateDevice(DEVICE_ID_1)));
        reclaimAccount(account);
        break;
      case CONFIRMED:
        accounts.reserveUsernameHash(account, usernameHash, Duration.ofMinutes(1)).join();
        accounts.confirmUsernameHash(account, usernameHash, encryptedUsername).join();
        break;
    }

    Optional<UUID> preservedLink = Optional.ofNullable(account.getUsernameLinkHandle());

    // re-register the account
    account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID(), List.of(generateDevice(DEVICE_ID_1)));
    reclaimAccount(account);

    // If we had a username link, or we had previously saved a username link from another re-registration, make sure
    // we preserve it
    accounts.confirmUsernameHash(account, usernameHash, encryptedUsername).join();

    boolean shouldReuseLink = switch (usernameStatus) {
      case RESERVED_WITH_SAVED_LINK, CONFIRMED -> true;
      case NONE, RESERVED -> false;
    };

    // If we had a reclaimable username, make sure we preserved the link.
    assertThat(Objects.equals(account.getUsernameLinkHandle(), preservedLink.orElse(null)))
        .isEqualTo(shouldReuseLink);

    // in all cases, we should now have usernameHash, usernameLink, and encryptedUsername set
    assertThat(account.getUsernameHash()).isNotEmpty();
    assertThat(account.getEncryptedUsername()).isNotEmpty();
    assertThat(account.getUsernameLinkHandle()).isNotNull();
    assertThat(account.getReservedUsernameHash()).isEmpty();
  }

  private void reclaimAccount(final Account reregisteredAccount) {
    final AccountAlreadyExistsException accountAlreadyExistsException =
        assertThrows(AccountAlreadyExistsException.class,
            () -> accounts.create(reregisteredAccount, new PrincipalVerificationDetails(
                PrincipalVerificationDetails.VerificationType.SESSION,
                "provider-example", "subject-example", reregisteredAccount.getPrincipal()),
                Collections.emptyList()));

    reregisteredAccount.setUuid(accountAlreadyExistsException.getExistingAccount().getUuid());
    reregisteredAccount.setPrincipal(accountAlreadyExistsException.getExistingAccount().getPrincipal(),
        accountAlreadyExistsException.getExistingAccount().getPrincipalNameIdentifier());

    assertDoesNotThrow(() -> accounts.reclaimAccount(accountAlreadyExistsException.getExistingAccount(),
        reregisteredAccount,
        Collections.emptyList()).toCompletableFuture().join());
  }

  @Test
  void testReclaimAccountPreservesFields() {
    final String principal = "user.account@example.com";
    final UUID existingUuid = UUID.randomUUID();
    final Account existingAccount =
        generateAccount(principal, existingUuid, UUID.randomUUID(), List.of(generateDevice(DEVICE_ID_1)));

    // the backup credential request and share-set are always preserved across account reclaims
    existingAccount.setBackupCredentialRequests(TestRandomUtil.nextBytes(32), TestRandomUtil.nextBytes(32));
    createAccount(existingAccount);
    final Account secondAccount =
        generateAccount(principal, UUID.randomUUID(), UUID.randomUUID(), List.of(generateDevice(DEVICE_ID_1)));

    reclaimAccount(secondAccount);

    final Account reclaimed = accounts.getByAccountIdentifier(existingUuid).orElseThrow();
    assertThat(reclaimed.getBackupCredentialRequest(BackupCredentialType.MESSAGES).orElseThrow())
        .isEqualTo(existingAccount.getBackupCredentialRequest(BackupCredentialType.MESSAGES).orElseThrow());
    assertThat(reclaimed.getBackupCredentialRequest(BackupCredentialType.MEDIA).orElseThrow())
        .isEqualTo(existingAccount.getBackupCredentialRequest(BackupCredentialType.MEDIA).orElseThrow());
  }

  @Test
  void testReclaimAccount() {
    final String principal = "user.account@example.com";
    final Device device = generateDevice(DEVICE_ID_1);
    final UUID existingUuid = UUID.randomUUID();
    final UUID existingPni = UUID.randomUUID();
    final Account existingAccount = generateAccount(principal, existingUuid, existingPni, List.of(device));

    // Backup vouchers should be carried over accross re-registration
    final Account.BackupVoucher bv = new Account.BackupVoucher(1, Instant.now().plus(Duration.ofDays(1)));
    existingAccount.setBackupVoucher(bv);

    createAccount(existingAccount);

    final byte[] usernameHash = TestRandomUtil.nextBytes(32);
    final byte[] encryptedUsername = TestRandomUtil.nextBytes(16);

    // Set up the existing account to have a username hash
    accounts.confirmUsernameHash(existingAccount, usernameHash, encryptedUsername).join();
    final UUID usernameLinkHandle = existingAccount.getUsernameLinkHandle();

    verifyStoredState(principal, existingAccount.getUuid(), existingAccount.getPrincipalNameIdentifier(), usernameHash, existingAccount, true);

    assertPrincipalConstraintExists(principal, existingUuid);
    assertPrincipalNameIdentifierConstraintExists(existingPni, existingUuid);

    assertDoesNotThrow(() -> accounts.update(existingAccount));

    final UUID secondUuid = UUID.randomUUID();

    final Device secondDevice = generateDevice(DEVICE_ID_1);
    final Account secondAccount = generateAccount(principal, secondUuid, UUID.randomUUID(), List.of(secondDevice));

    reclaimAccount(secondAccount);

    // usernameHash should be unset
    verifyStoredState("user.account@example.com", existingUuid, existingPni, null, secondAccount, true);

    // username should become 'reclaimable'
    Map<String, AttributeValue> item = readAccount(existingUuid);
    Account result = Accounts.fromItem(item);
    assertThat(AttributeValues.getUUID(item, Accounts.ATTR_USERNAME_LINK_UUID, null))
        .isEqualTo(usernameLinkHandle)
        .isEqualTo(result.getUsernameLinkHandle());
    assertThat(result.getUsernameHash()).isEmpty();
    assertThat(result.getEncryptedUsername()).isEmpty();
    assertArrayEquals(result.getReservedUsernameHash().orElseThrow(), usernameHash);

    assertThat(result.getBackupVoucher()).isEqualTo(bv);

    // should keep the same usernameLink, now encryptedUsername should be set
    accounts.confirmUsernameHash(result, usernameHash, encryptedUsername).join();
    item = readAccount(existingUuid);
    result = Accounts.fromItem(item);
    assertThat(AttributeValues.getUUID(item, Accounts.ATTR_USERNAME_LINK_UUID, null))
        .isEqualTo(usernameLinkHandle)
        .isEqualTo(result.getUsernameLinkHandle());
    assertArrayEquals(encryptedUsername, result.getEncryptedUsername().orElseThrow());
    assertArrayEquals(usernameHash, result.getUsernameHash().orElseThrow());
    assertThat(result.getReservedUsernameHash()).isEmpty();

    assertPrincipalConstraintExists("user.account@example.com", existingUuid);
    assertPrincipalNameIdentifierConstraintExists(existingPni, existingUuid);

    Account invalidAccount = generateAccount("another.user.account@example.com", existingUuid, UUID.randomUUID(), List.of(generateDevice(DEVICE_ID_1)));

    assertThatThrownBy(() -> createAccount(invalidAccount));
  }

  @Test
  void testUpdate() {
    Device device = generateDevice(DEVICE_ID_1);
    Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID(), List.of(device));

    createAccount(account);

    assertPrincipalConstraintExists("user.account@example.com", account.getUuid());
    assertPrincipalNameIdentifierConstraintExists(account.getPrincipalNameIdentifier(), account.getUuid());

    device.setName("foobar".getBytes(StandardCharsets.UTF_8));

    accounts.update(account);

    assertPrincipalConstraintExists("user.account@example.com", account.getUuid());
    assertPrincipalNameIdentifierConstraintExists(account.getPrincipalNameIdentifier(), account.getUuid());

    Optional<Account> retrieved = accounts.getByPrincipal("user.account@example.com");

    assertThat(retrieved.isPresent()).isTrue();
    verifyStoredState("user.account@example.com", account.getUuid(), account.getPrincipalNameIdentifier(), null, retrieved.get(), account);

    retrieved = accounts.getByAccountIdentifier(account.getUuid());

    assertThat(retrieved.isPresent()).isTrue();
    verifyStoredState("user.account@example.com", account.getUuid(), account.getPrincipalNameIdentifier(), null, account, true);

    device = generateDevice(DEVICE_ID_1);
    Account unknownAccount = generateAccount("another.user.account@example.com", UUID.randomUUID(), UUID.randomUUID(), List.of(device));

    assertThatThrownBy(() -> accounts.update(unknownAccount)).isInstanceOfAny(ConditionalCheckFailedException.class);

    accounts.update(account);

    assertThat(account.getVersion()).isEqualTo(2);

    verifyStoredState("user.account@example.com", account.getUuid(), account.getPrincipalNameIdentifier(), null, account, true);

    account.setVersion(1);

    assertThatThrownBy(() -> accounts.update(account)).isInstanceOfAny(ContestedOptimisticLockException.class);

    account.setVersion(2);

    accounts.update(account);

    verifyStoredState("user.account@example.com", account.getUuid(), account.getPrincipalNameIdentifier(), null, account, true);
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void testUpdateWithMockTransactionConflictException(boolean wrapException) {

    final DynamoDbAsyncClient dynamoDbAsyncClient = mock(DynamoDbAsyncClient.class);
    accounts = new Accounts(
        clock,
        mock(DynamoDbClient.class),
        dynamoDbAsyncClient,
        Tables.ACCOUNTS.tableName(),
        Tables.PRINCIPALS.tableName(),
        Tables.PNI_ASSIGNMENTS.tableName(),
        Tables.SUBJECTS.tableName(),
        Tables.USERNAMES.tableName(),
        Tables.DELETED_ACCOUNTS.tableName(),
        Tables.USED_LINK_DEVICE_TOKENS.tableName());

    Exception e = TransactionConflictException.builder().build();
    e = wrapException ? new CompletionException(e) : e;

    when(dynamoDbAsyncClient.updateItem(any(UpdateItemRequest.class)))
        .thenReturn(CompletableFuture.failedFuture(e));

    Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID());

    assertThatThrownBy(() -> accounts.update(account)).isInstanceOfAny(ContestedOptimisticLockException.class);
  }

  @Test
  void testUpdateTransactionally() {
    final Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account);

    final byte[] deviceName = "device-name".getBytes(StandardCharsets.UTF_8);

    assertNotEquals(deviceName,
        accounts.getByAccountIdentifier(account.getUuid()).orElseThrow().getPrimaryDevice().getName());

    assertFalse(DYNAMO_DB_EXTENSION.getDynamoDbClient().getItem(GetItemRequest.builder()
            .tableName(Tables.CLIENT_RELEASES.tableName())
            .key(Map.of(
                ClientReleases.ATTR_PLATFORM, AttributeValues.fromString("test"),
                ClientReleases.ATTR_VERSION, AttributeValues.fromString("test")
            ))
            .build())
        .hasItem());

    account.getPrimaryDevice().setName(deviceName);

    accounts.updateTransactionallyAsync(account, List.of(TransactWriteItem.builder()
        .put(Put.builder()
            .tableName(Tables.CLIENT_RELEASES.tableName())
            .item(Map.of(
                ClientReleases.ATTR_PLATFORM, AttributeValues.fromString("test"),
                ClientReleases.ATTR_VERSION, AttributeValues.fromString("test")
            ))
            .build())
        .build())).toCompletableFuture().join();

    assertArrayEquals(deviceName,
        accounts.getByAccountIdentifier(account.getUuid()).orElseThrow().getPrimaryDevice().getName());

    assertTrue(DYNAMO_DB_EXTENSION.getDynamoDbClient().getItem(GetItemRequest.builder()
            .tableName(Tables.CLIENT_RELEASES.tableName())
            .key(Map.of(
                ClientReleases.ATTR_PLATFORM, AttributeValues.fromString("test"),
                ClientReleases.ATTR_VERSION, AttributeValues.fromString("test")
            ))
            .build())
        .hasItem());
  }

  @Test
  void testUpdateTransactionallyContestedLock() {
    final Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account);

    account.setVersion(account.getVersion() - 1);

    final CompletionException completionException = assertThrows(CompletionException.class,
        () -> accounts.updateTransactionallyAsync(account, List.of(TransactWriteItem.builder()
            .put(Put.builder()
                .tableName(Tables.CLIENT_RELEASES.tableName())
                .item(Map.of(
                    ClientReleases.ATTR_PLATFORM, AttributeValues.fromString("test"),
                    ClientReleases.ATTR_VERSION, AttributeValues.fromString("test")
                ))
                .build())
            .build())).toCompletableFuture().join());

    assertInstanceOf(ContestedOptimisticLockException.class, completionException.getCause());
  }

  @Test
  void testUpdateTransactionallyWithMockTransactionConflictException() {
    final DynamoDbAsyncClient dynamoDbAsyncClient = mock(DynamoDbAsyncClient.class);

    accounts = new Accounts(
        clock,
        mock(DynamoDbClient.class),
        dynamoDbAsyncClient,
        Tables.ACCOUNTS.tableName(),
        Tables.PRINCIPALS.tableName(),
        Tables.PNI_ASSIGNMENTS.tableName(),
        Tables.SUBJECTS.tableName(),
        Tables.USERNAMES.tableName(),
        Tables.DELETED_ACCOUNTS.tableName(),
        Tables.USED_LINK_DEVICE_TOKENS.tableName());

    when(dynamoDbAsyncClient.transactWriteItems(any(TransactWriteItemsRequest.class)))
        .thenReturn(CompletableFuture.failedFuture(TransactionCanceledException.builder()
            .cancellationReasons(CancellationReason.builder()
                .code("TransactionConflict")
                .build())
            .build()));

    Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID());

    assertThatThrownBy(() -> accounts.updateTransactionallyAsync(account, Collections.emptyList()).toCompletableFuture().join())
        .isInstanceOfAny(CompletionException.class)
        .hasCauseInstanceOf(ContestedOptimisticLockException.class);
  }

  @Test
  void testGetAll() {
    final List<Account> expectedAccounts = new ArrayList<>();

    for (int i = 1; i <= 100; i++) {
      final Account account = generateAccount("+1" + String.format("%03d", i), UUID.randomUUID(), UUID.randomUUID());
      expectedAccounts.add(account);
      createAccount(account);
    }

    final List<Account> retrievedAccounts =
        accounts.getAll(2, Schedulers.parallel()).collectList().block();

    assertNotNull(retrievedAccounts);
    assertEquals(expectedAccounts.stream().map(Account::getUuid).collect(Collectors.toSet()),
        retrievedAccounts.stream().map(Account::getUuid).collect(Collectors.toSet()));
  }

  @Test
  void testGetAllAccountIdentifiers() {
    final Set<UUID> expectedAccountIdentifiers = new HashSet<>();

    for (int i = 1; i <= 100; i++) {
      final Account account = generateAccount("+1" + String.format("%03d", i), UUID.randomUUID(), UUID.randomUUID());
      expectedAccountIdentifiers.add(account.getIdentifier(IdentityType.ACI));
      createAccount(account);
    }

    @SuppressWarnings("DataFlowIssue") final Set<UUID> retrievedAccountIdentifiers =
        new HashSet<>(accounts.getAllAccountIdentifiers(2, Schedulers.parallel()).collectList().block());

    assertEquals(expectedAccountIdentifiers, retrievedAccountIdentifiers);
  }

  @Test
  void testDelete() {
    final Device deletedDevice = generateDevice(DEVICE_ID_1);
    final Account deletedAccount = generateAccount("deleted.account@example.com", UUID.randomUUID(),
        UUID.randomUUID(), List.of(deletedDevice));
    final Device retainedDevice = generateDevice(DEVICE_ID_1);
    final Account retainedAccount = generateAccount("retained.account@example.com", UUID.randomUUID(),
        UUID.randomUUID(), List.of(retainedDevice));

    createAccount(deletedAccount);
    createAccount(retainedAccount);

    assertThat(accounts.findRecentlyDeletedAccountIdentifier(deletedAccount.getPrincipalNameIdentifier())).isEmpty();

    assertPrincipalConstraintExists("deleted.account@example.com", deletedAccount.getUuid());
    assertPrincipalNameIdentifierConstraintExists(deletedAccount.getPrincipalNameIdentifier(), deletedAccount.getUuid());
    assertPrincipalConstraintExists("retained.account@example.com", retainedAccount.getUuid());
    assertPrincipalNameIdentifierConstraintExists(retainedAccount.getPrincipalNameIdentifier(), retainedAccount.getUuid());

    assertThat(accounts.getByAccountIdentifier(deletedAccount.getUuid())).isPresent();
    assertThat(accounts.getByAccountIdentifier(retainedAccount.getUuid())).isPresent();

    accounts.delete(deletedAccount.getUuid(), Collections.emptyList()).join();

    assertThat(accounts.getByAccountIdentifier(deletedAccount.getUuid())).isNotPresent();
    assertThat(accounts.findRecentlyDeletedAccountIdentifier(deletedAccount.getPrincipalNameIdentifier())).hasValue(deletedAccount.getUuid());

    assertPrincipalConstraintDoesNotExist(deletedAccount.getPrincipal());
    assertPrincipalNameIdentifierConstraintDoesNotExist(deletedAccount.getPrincipalNameIdentifier());

    verifyStoredState(retainedAccount.getPrincipal(), retainedAccount.getUuid(), retainedAccount.getPrincipalNameIdentifier(),
        null, accounts.getByAccountIdentifier(retainedAccount.getUuid()).orElseThrow(), retainedAccount);

    {
      final Account recreatedAccount = generateAccount(deletedAccount.getPrincipal(), UUID.randomUUID(),
          deletedAccount.getPrincipalNameIdentifier(), List.of(generateDevice(DEVICE_ID_1)));

      final boolean freshUser = createAccount(recreatedAccount);

      assertThat(freshUser).isTrue();
      assertThat(accounts.getByAccountIdentifier(recreatedAccount.getUuid())).isPresent();
      verifyStoredState(recreatedAccount.getPrincipal(), recreatedAccount.getUuid(), recreatedAccount.getPrincipalNameIdentifier(),
          null, accounts.getByAccountIdentifier(recreatedAccount.getUuid()).orElseThrow(), recreatedAccount);

      assertPrincipalConstraintExists(recreatedAccount.getPrincipal(), recreatedAccount.getUuid());
      assertPrincipalNameIdentifierConstraintExists(recreatedAccount.getPrincipalNameIdentifier(), recreatedAccount.getUuid());
    }
  }

  @Test
  void testMissing() {
    Device device = generateDevice(DEVICE_ID_1);
    Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID(), List.of(device));

    createAccount(account);

    Optional<Account> retrieved = accounts.getByPrincipal("does.not.exist@example.com");
    assertThat(retrieved.isPresent()).isFalse();

    retrieved = accounts.getByAccountIdentifier(UUID.randomUUID());
    assertThat(retrieved.isPresent()).isFalse();
  }

  @Test
  void getByAccountIdentifierAsync() {
    assertThat(accounts.getByAccountIdentifierAsync(UUID.randomUUID()).join()).isEmpty();

    final Account account =
        generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID(), List.of(generateDevice(DEVICE_ID_1)));

    createAccount(account);

    assertThat(accounts.getByAccountIdentifierAsync(account.getUuid()).join()).isPresent();
  }

  @Test
  void getByPrincipalNameIdentifierAsync() {
    assertThat(accounts.getByPrincipalNameIdentifierAsync(UUID.randomUUID()).join()).isEmpty();

    final Account account =
        generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID(), List.of(generateDevice(DEVICE_ID_1)));

    createAccount(account);

    assertThat(accounts.getByPrincipalNameIdentifierAsync(account.getPrincipalNameIdentifier()).join()).isPresent();
  }

  @Test
  void getByPrincipalAsync() {
    final String principal = "user.account@example.com";

    assertThat(accounts.getByPrincipalAsync(principal).join()).isEmpty();

    final Account account =
        generateAccount(principal, UUID.randomUUID(), UUID.randomUUID(), List.of(generateDevice(DEVICE_ID_1)));

    createAccount(account);

    assertThat(accounts.getByPrincipalAsync(principal).join()).isPresent();
  }

  @Test
  void testCanonicallyDiscoverableSet() {
    Device device = generateDevice(DEVICE_ID_1);
    Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID(), List.of(device));
    account.setDiscoverableByPrincipal(false);
    createAccount(account);
    verifyStoredState("user.account@example.com", account.getUuid(), account.getPrincipalNameIdentifier(), null, account, false);
    account.setDiscoverableByPrincipal(true);
    accounts.update(account);
    verifyStoredState("user.account@example.com", account.getUuid(), account.getPrincipalNameIdentifier(), null, account, true);
    account.setDiscoverableByPrincipal(false);
    accounts.update(account);
    verifyStoredState("user.account@example.com", account.getUuid(), account.getPrincipalNameIdentifier(), null, account, false);
  }

  @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
  @ParameterizedTest
  @MethodSource
  public void testChangePrincipal(final Optional<UUID> maybeDisplacedAccountIdentifier) {
    final String originalPrincipal = "original.principal@example.com";
    final String targetPrincipal = "target.principal@example.com";

    final UUID originalPni = UUID.randomUUID();
    final UUID targetPni = UUID.randomUUID();

    final Device device = generateDevice(DEVICE_ID_1);
    final Account account = generateAccount(originalPrincipal, UUID.randomUUID(), originalPni, List.of(device));

    createAccount(account);

    assertThat(accounts.getByPrincipalNameIdentifier(originalPni)).isPresent();

    assertPrincipalConstraintExists(originalPrincipal, account.getUuid());
    assertPrincipalNameIdentifierConstraintExists(originalPni, account.getUuid());

    {
      final Optional<Account> retrieved = accounts.getByPrincipal(originalPrincipal);
      assertThat(retrieved).isPresent();

      verifyStoredState(originalPrincipal, account.getUuid(), account.getPrincipalNameIdentifier(), null, retrieved.get(), account);
    }

    accounts.changePrincipal(account, targetPrincipal, targetPni, maybeDisplacedAccountIdentifier, Collections.emptyList());

    assertThat(accounts.getByPrincipal(originalPrincipal)).isEmpty();
    assertThat(accounts.getByAccountIdentifier(originalPni)).isEmpty();

    assertPrincipalConstraintDoesNotExist(originalPrincipal);
    assertPrincipalNameIdentifierConstraintDoesNotExist(originalPni);
    assertPrincipalConstraintExists(targetPrincipal, account.getUuid());
    assertPrincipalNameIdentifierConstraintExists(targetPni, account.getUuid());

    {
      final Optional<Account> retrieved = accounts.getByPrincipal(targetPrincipal);
      assertThat(retrieved).isPresent();

      verifyStoredState(targetPrincipal, account.getUuid(), account.getPrincipalNameIdentifier(), null, retrieved.get(), account);

      assertThat(retrieved.get().getPrincipalNameIdentifier()).isEqualTo(targetPni);
      assertThat(accounts.getByPrincipalNameIdentifier(targetPni)).isPresent();
    }

    assertThat(accounts.findRecentlyDeletedAccountIdentifier(originalPni)).isEqualTo(maybeDisplacedAccountIdentifier);
  }

  private static Stream<Arguments> testChangePrincipal() {
    return Stream.of(
        Arguments.of(Optional.empty()),
        Arguments.of(Optional.of(UUID.randomUUID()))
    );
  }

  @Test
  public void testChangePrincipalConflict() {
    final String originalPrincipal = "original.principal@example.com";
    final String targetPrincipal = "target.principal@example.com";

    final UUID originalPni = UUID.randomUUID();
    final UUID targetPni = UUID.randomUUID();

    final Device existingDevice = generateDevice(DEVICE_ID_1);
    final Account existingAccount = generateAccount(targetPrincipal, UUID.randomUUID(), targetPni, List.of(existingDevice));

    final Device device = generateDevice(DEVICE_ID_1);
    final Account account = generateAccount(originalPrincipal, UUID.randomUUID(), originalPni, List.of(device));

    createAccount(account);
    createAccount(existingAccount);

    assertThrows(TransactionCanceledException.class, () -> accounts.changePrincipal(account, targetPrincipal, targetPni, Optional.of(existingAccount.getUuid()), Collections.emptyList()));

    assertPrincipalConstraintExists(originalPrincipal, account.getUuid());
    assertPrincipalNameIdentifierConstraintExists(originalPni, account.getUuid());
    assertPrincipalConstraintExists(targetPrincipal, existingAccount.getUuid());
    assertPrincipalNameIdentifierConstraintExists(targetPni, existingAccount.getUuid());
  }

  @Test
  public void testChangePrincipalPrincipalNameIdentifierConflict() {
    final String originalPrincipal = "original.principal@example.com";
    final String targetPrincipal = "target.principal@example.com";

    final Device device = generateDevice(DEVICE_ID_1);
    final Account account = generateAccount(originalPrincipal, UUID.randomUUID(), UUID.randomUUID(), List.of(device));

    createAccount(account);

    final UUID existingAccountIdentifier = UUID.randomUUID();
    final UUID existingPrincipalNameIdentifier = UUID.randomUUID();

    // Artificially inject a conflicting PNI entry
    DYNAMO_DB_EXTENSION.getDynamoDbClient().putItem(PutItemRequest.builder()
        .tableName(Tables.PNI_ASSIGNMENTS.tableName())
        .item(Map.of(
            Accounts.ATTR_PNI_UUID, AttributeValues.fromUUID(existingPrincipalNameIdentifier),
            Accounts.KEY_ACCOUNT_UUID, AttributeValues.fromUUID(existingAccountIdentifier)))
        .conditionExpression(
            "attribute_not_exists(#pni) OR (attribute_exists(#pni) AND #uuid = :uuid)")
        .expressionAttributeNames(
            Map.of("#uuid", Accounts.KEY_ACCOUNT_UUID,
                "#pni", Accounts.ATTR_PNI_UUID))
        .expressionAttributeValues(
            Map.of(":uuid", AttributeValues.fromUUID(existingAccountIdentifier)))
        .build());

    assertThrows(TransactionCanceledException.class, () -> accounts.changePrincipal(account, targetPrincipal, existingPrincipalNameIdentifier, Optional.empty(), Collections.emptyList()));
  }

  @Test
  public void testChangePrincipalContestedOptimisticLock() {
    final String originalPrincipal = "original.principal@example.com";
    final String targetPrincipal = "target.principal@example.com";

    final UUID originalPni = UUID.randomUUID();
    final UUID targetPni = UUID.randomUUID();

    final Device device = generateDevice(DEVICE_ID_1);
    final Account firstAccountInstance = generateAccount(originalPrincipal, UUID.randomUUID(), originalPni,
        List.of(device));

    createAccount(firstAccountInstance);

    final Account secondAccountInstance = accounts.getByAccountIdentifier(firstAccountInstance.getUuid()).orElseThrow();

    // update via the first instance, which will update the version
    firstAccountInstance.setCurrentProfileVersion("1");
    accounts.update(firstAccountInstance);

    assertThrows(ContestedOptimisticLockException.class,
        () -> accounts.changePrincipal(secondAccountInstance, targetPrincipal, targetPni, Optional.empty(),
            Collections.emptyList()), "Second account instance has stale version");

    final Account refreshedAccountInstance = accounts.getByAccountIdentifier(firstAccountInstance.getUuid())
        .orElseThrow();
    accounts.changePrincipal(refreshedAccountInstance, targetPrincipal, targetPni, Optional.empty(),
        Collections.emptyList());

    assertPrincipalConstraintDoesNotExist(originalPrincipal);
    assertPrincipalNameIdentifierConstraintDoesNotExist(originalPni);
    assertPrincipalConstraintExists(targetPrincipal, firstAccountInstance.getUuid());
    assertPrincipalNameIdentifierConstraintExists(targetPni, firstAccountInstance.getUuid());
  }

  @Test
  void testSwitchUsernameHashes() {
    final Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account);

    assertThat(accounts.getByUsernameHash(USERNAME_HASH_1).join()).isEmpty();

    accounts.reserveUsernameHash(account, USERNAME_HASH_1, Duration.ofDays(1)).join();
    accounts.confirmUsernameHash(account, USERNAME_HASH_1, ENCRYPTED_USERNAME_1).join();
    final UUID oldHandle = account.getUsernameLinkHandle();

    {
      final Optional<Account> maybeAccount = accounts.getByUsernameHash(USERNAME_HASH_1).join();
      verifyStoredState(account.getPrincipal(), account.getUuid(), account.getPrincipalNameIdentifier(), USERNAME_HASH_1, maybeAccount.orElseThrow(), account);

      final Optional<Account> maybeAccount2 = accounts.getByUsernameLinkHandle(oldHandle).join();
      verifyStoredState(account.getPrincipal(), account.getUuid(), account.getPrincipalNameIdentifier(), USERNAME_HASH_1, maybeAccount2.orElseThrow(), account);
    }

    accounts.reserveUsernameHash(account, USERNAME_HASH_2, Duration.ofDays(1)).join();
    accounts.confirmUsernameHash(account, USERNAME_HASH_2, ENCRYPTED_USERNAME_2).join();
    final UUID newHandle = account.getUsernameLinkHandle();

    // switching usernames should put a hold on our original username
    assertThat(accounts.getByUsernameHash(USERNAME_HASH_1).join()).isEmpty();
    assertThat(getUsernameConstraintTableItem(USERNAME_HASH_1)).containsExactlyInAnyOrderEntriesOf(Map.of(
        Accounts.UsernameTable.KEY_USERNAME_HASH, AttributeValues.b(USERNAME_HASH_1),
        Accounts.UsernameTable.ATTR_ACCOUNT_UUID, AttributeValues.b(account.getUuid()),
        Accounts.UsernameTable.ATTR_CONFIRMED, AttributeValues.fromBool(false),
        Accounts.UsernameTable.ATTR_TTL,
        AttributeValues.n(clock.instant().plus(Accounts.USERNAME_HOLD_DURATION).getEpochSecond())));
    assertThat(accounts.getByUsernameLinkHandle(oldHandle).join()).isEmpty();

    {
      final Optional<Account> maybeAccount = accounts.getByUsernameHash(USERNAME_HASH_2).join();

      assertThat(maybeAccount).isPresent();
      verifyStoredState(account.getPrincipal(), account.getUuid(), account.getPrincipalNameIdentifier(),
          USERNAME_HASH_2, maybeAccount.orElseThrow(), account);
      final Optional<Account> maybeAccount2 = accounts.getByUsernameLinkHandle(newHandle).join();
      verifyStoredState(account.getPrincipal(), account.getUuid(), account.getPrincipalNameIdentifier(),
          USERNAME_HASH_2, maybeAccount2.orElseThrow(), account);
    }
  }

  @Test
  void testUsernameHashNotAvailable() {
    final Account firstAccount = generateAccount("user.account1@example.com", UUID.randomUUID(), UUID.randomUUID());
    final Account secondAccount = generateAccount("user.account2@example.com", UUID.randomUUID(), UUID.randomUUID());

    createAccount(firstAccount);
    createAccount(secondAccount);

    // first account reserves and confirms username hash
    assertThatNoException().isThrownBy(() -> {
      accounts.reserveUsernameHash(firstAccount, USERNAME_HASH_1, Duration.ofDays(1)).join();
      accounts.confirmUsernameHash(firstAccount, USERNAME_HASH_1, ENCRYPTED_USERNAME_1).join();
    });

    final Optional<Account> maybeAccount = accounts.getByUsernameHash(USERNAME_HASH_1).join();

    assertThat(maybeAccount).isPresent();
    verifyStoredState(firstAccount.getPrincipal(), firstAccount.getUuid(), firstAccount.getPrincipalNameIdentifier(), USERNAME_HASH_1, maybeAccount.get(), firstAccount);

    // throw an error if second account tries to reserve or confirm the same username hash
    CompletableFutureTestUtil.assertFailsWithCause(UsernameHashNotAvailableException.class,
        accounts.reserveUsernameHash(secondAccount, USERNAME_HASH_1, Duration.ofDays(1)));
    CompletableFutureTestUtil.assertFailsWithCause(UsernameHashNotAvailableException.class,
        accounts.confirmUsernameHash(secondAccount, USERNAME_HASH_1, ENCRYPTED_USERNAME_1));

    // throw an error if first account tries to reserve or confirm the username hash that it has already confirmed
    CompletableFutureTestUtil.assertFailsWithCause(UsernameHashNotAvailableException.class,
        accounts.reserveUsernameHash(firstAccount, USERNAME_HASH_1, Duration.ofDays(1)));
    CompletableFutureTestUtil.assertFailsWithCause(UsernameHashNotAvailableException.class,
        accounts.confirmUsernameHash(firstAccount, USERNAME_HASH_1, ENCRYPTED_USERNAME_1));

    assertThat(secondAccount.getReservedUsernameHash()).isEmpty();
    assertThat(secondAccount.getUsernameHash()).isEmpty();
  }

  @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
  @ParameterizedTest
  @MethodSource
  void testReserveUsernameHashTransactionConflict(final Optional<String> constraintCancellationString,
      final Optional<String> accountsCancellationString,
      final Class<Exception> expectedException) {
    final DynamoDbAsyncClient dbAsyncClient = mock(DynamoDbAsyncClient.class);

    accounts = new Accounts(
        clock,
        mock(DynamoDbClient.class),
        dbAsyncClient,
        Tables.ACCOUNTS.tableName(),
        Tables.PRINCIPALS.tableName(),
        Tables.PNI_ASSIGNMENTS.tableName(),
        Tables.SUBJECTS.tableName(),
        Tables.USERNAMES.tableName(),
        Tables.DELETED_ACCOUNTS.tableName(),
        Tables.USED_LINK_DEVICE_TOKENS.tableName());
    final Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account);

    final CancellationReason constraintCancellationReason = constraintCancellationString.map(
        reason -> CancellationReason.builder().code(reason).build()
    ).orElse(CancellationReason.builder().build());

    final CancellationReason accountsCancellationReason = accountsCancellationString.map(
        reason -> CancellationReason.builder().code(reason).build()
    ).orElse(CancellationReason.builder().build());

    when(dbAsyncClient.transactWriteItems(any(TransactWriteItemsRequest.class)))
        .thenReturn(CompletableFuture.failedFuture(TransactionCanceledException.builder()
            .cancellationReasons(constraintCancellationReason, accountsCancellationReason)
            .build()));

    CompletableFutureTestUtil.assertFailsWithCause(expectedException,
        accounts.reserveUsernameHash(account, USERNAME_HASH_1, Duration.ofDays(1)));
  }

  private static Stream<Arguments> testReserveUsernameHashTransactionConflict() {
    return Stream.of(
        Arguments.of(Optional.of("TransactionConflict"), Optional.empty(), ContestedOptimisticLockException.class),
        Arguments.of(Optional.empty(), Optional.of("TransactionConflict"), ContestedOptimisticLockException.class),
        Arguments.of(Optional.of("ConditionalCheckFailed"), Optional.of("TransactionConflict"), UsernameHashNotAvailableException.class)
    );
  }

  @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
  @ParameterizedTest
  @MethodSource
  void testConfirmUsernameHashTransactionConflict(final Optional<String> constraintCancellationString,
      final Optional<String> accountsCancellationString,
      final Class<Exception> expectedException) {
    final DynamoDbAsyncClient dbAsyncClient = mock(DynamoDbAsyncClient.class);

    accounts = new Accounts(
        clock,
        mock(DynamoDbClient.class),
        dbAsyncClient,
        Tables.ACCOUNTS.tableName(),
        Tables.PRINCIPALS.tableName(),
        Tables.PNI_ASSIGNMENTS.tableName(),
        Tables.SUBJECTS.tableName(),
        Tables.USERNAMES.tableName(),
        Tables.DELETED_ACCOUNTS.tableName(),
        Tables.USED_LINK_DEVICE_TOKENS.tableName());
    final Account account = generateAccount("user.account1@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account);

    final CancellationReason constraintCancellationReason = constraintCancellationString.map(
        reason -> CancellationReason.builder().code(reason).build()
    ).orElse(CancellationReason.builder().build());

    final CancellationReason accountsCancellationReason = accountsCancellationString.map(
        reason -> CancellationReason.builder().code(reason).build()
    ).orElse(CancellationReason.builder().build());

    when(dbAsyncClient.transactWriteItems(any(TransactWriteItemsRequest.class)))
        .thenReturn(CompletableFuture.failedFuture(TransactionCanceledException.builder()
            .cancellationReasons(constraintCancellationReason,
                accountsCancellationReason,
                CancellationReason.builder().build())
            .build()));

    CompletableFutureTestUtil.assertFailsWithCause(expectedException,
        accounts.confirmUsernameHash(account, USERNAME_HASH_1, ENCRYPTED_USERNAME_1));
  }

  private static Stream<Arguments> testConfirmUsernameHashTransactionConflict() {
    return Stream.of(
        Arguments.of(Optional.of("TransactionConflict"), Optional.empty(), ContestedOptimisticLockException.class),
        Arguments.of(Optional.empty(), Optional.of("TransactionConflict"), ContestedOptimisticLockException.class),
        Arguments.of(Optional.of("ConditionalCheckFailed"), Optional.of("TransactionConflict"), UsernameHashNotAvailableException.class)
    );
  }

  @Test
  void testConfirmUsernameHashVersionMismatch() {
    final Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account);
    accounts.reserveUsernameHash(account, USERNAME_HASH_1, Duration.ofDays(1)).join();
    account.setVersion(account.getVersion() + 77);

    CompletableFutureTestUtil.assertFailsWithCause(ContestedOptimisticLockException.class,
        accounts.confirmUsernameHash(account, USERNAME_HASH_1, ENCRYPTED_USERNAME_1));

    assertThat(account.getUsernameHash()).isEmpty();
  }

  @Test
  void testClearUsername() {
    final Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account);

    accounts.reserveUsernameHash(account, USERNAME_HASH_1, Duration.ofDays(1)).join();
    accounts.confirmUsernameHash(account, USERNAME_HASH_1, ENCRYPTED_USERNAME_1).join();
    assertThat(accounts.getByUsernameHash(USERNAME_HASH_1).join()).isPresent();

    accounts.clearUsernameHash(account).join();

    assertThat(accounts.getByUsernameHash(USERNAME_HASH_1).join()).isEmpty();
    assertThat(accounts.getByAccountIdentifier(account.getUuid()))
        .hasValueSatisfying(clearedAccount -> {
          assertThat(clearedAccount.getUsernameHash()).isEmpty();
          assertThat(clearedAccount.getUsernameLinkHandle()).isNull();
          assertThat(clearedAccount.getEncryptedUsername()).isEmpty();
        });
  }

  @Test
  void testClearUsernameNoUsername() {
    final Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account);

    assertThatNoException().isThrownBy(() -> accounts.clearUsernameHash(account).join());
  }

  @Test
  void testClearUsernameVersionMismatch() {
    final Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account);

    accounts.reserveUsernameHash(account, USERNAME_HASH_1, Duration.ofDays(1)).join();
    accounts.confirmUsernameHash(account, USERNAME_HASH_1, ENCRYPTED_USERNAME_1).join();

    account.setVersion(account.getVersion() + 12);

    CompletableFutureTestUtil.assertFailsWithCause(ContestedOptimisticLockException.class,
        accounts.clearUsernameHash(account));

    assertArrayEquals(USERNAME_HASH_1, account.getUsernameHash().orElseThrow());
  }

  @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
  @ParameterizedTest
  @MethodSource
  void testClearUsernameTransactionConflict(final Optional<String> constraintCancellationString,
      final Optional<String> accountsCancellationString) {
    final DynamoDbAsyncClient dbAsyncClient = mock(DynamoDbAsyncClient.class);

    accounts = new Accounts(
        clock,
        mock(DynamoDbClient.class),
        dbAsyncClient,
        Tables.ACCOUNTS.tableName(),
        Tables.PRINCIPALS.tableName(),
        Tables.PNI_ASSIGNMENTS.tableName(),
        Tables.SUBJECTS.tableName(),
        Tables.USERNAMES.tableName(),
        Tables.DELETED_ACCOUNTS.tableName(),
        Tables.USED_LINK_DEVICE_TOKENS.tableName());

    final Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account);

    when(dbAsyncClient.transactWriteItems(any(TransactWriteItemsRequest.class)))
        .thenReturn(CompletableFuture.completedFuture(mock(TransactWriteItemsResponse.class)));

    accounts.reserveUsernameHash(account, USERNAME_HASH_1, Duration.ofDays(1)).join();
    accounts.confirmUsernameHash(account, USERNAME_HASH_1, ENCRYPTED_USERNAME_1).join();

    final CancellationReason constraintCancellationReason = constraintCancellationString.map(
        reason -> CancellationReason.builder().code(reason).build()
    ).orElse(CancellationReason.builder().build());

    final CancellationReason accountsCancellationReason = accountsCancellationString.map(
        reason -> CancellationReason.builder().code(reason).build()
    ).orElse(CancellationReason.builder().build());

    when(dbAsyncClient.transactWriteItems(any(TransactWriteItemsRequest.class)))
        .thenReturn(CompletableFuture.failedFuture(TransactionCanceledException.builder()
            .cancellationReasons(accountsCancellationReason, constraintCancellationReason)
            .build()));

    CompletableFutureTestUtil.assertFailsWithCause(ContestedOptimisticLockException.class,
        accounts.clearUsernameHash(account));

    assertArrayEquals(USERNAME_HASH_1, account.getUsernameHash().orElseThrow());
  }

  private static Stream<Arguments> testClearUsernameTransactionConflict() {
    return Stream.of(
        Arguments.of(Optional.empty(), Optional.of("TransactionConflict"), ContestedOptimisticLockException.class),
        Arguments.of(Optional.of("TransactionConflict"), Optional.empty(), ContestedOptimisticLockException.class)
    );
  }

  @Test
  void testReservedUsernameHash() {
    final Account account1 = generateAccount("user.account1@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account1);
    final Account account2 = generateAccount("user.account2@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account2);

    accounts.reserveUsernameHash(account1, USERNAME_HASH_1, Duration.ofDays(1)).join();
    assertArrayEquals(USERNAME_HASH_1, account1.getReservedUsernameHash().orElseThrow());
    assertThat(account1.getUsernameHash()).isEmpty();

    // account 2 shouldn't be able to reserve or confirm the same username hash
    CompletableFutureTestUtil.assertFailsWithCause(UsernameHashNotAvailableException.class,
        accounts.reserveUsernameHash(account2, USERNAME_HASH_1, Duration.ofDays(1)));
    CompletableFutureTestUtil.assertFailsWithCause(UsernameHashNotAvailableException.class,
        accounts.confirmUsernameHash(account2, USERNAME_HASH_1, ENCRYPTED_USERNAME_1));
    assertThat(accounts.getByUsernameHash(USERNAME_HASH_1).join()).isEmpty();

    accounts.confirmUsernameHash(account1, USERNAME_HASH_1, ENCRYPTED_USERNAME_1).join();
    assertThat(account1.getReservedUsernameHash()).isEmpty();
    assertArrayEquals(USERNAME_HASH_1, account1.getUsernameHash().orElseThrow());
    assertThat(accounts.getByUsernameHash(USERNAME_HASH_1).join().orElseThrow().getUuid()).isEqualTo(account1.getUuid());

    final Map<String, AttributeValue> usernameConstraintRecord = getUsernameConstraintTableItem(USERNAME_HASH_1);

    assertThat(usernameConstraintRecord).containsKey(Accounts.UsernameTable.KEY_USERNAME_HASH);
    assertThat(usernameConstraintRecord).doesNotContainKey(Accounts.UsernameTable.ATTR_TTL);
  }

  @Test
  void switchBetweenReservedUsernameHashes() {
    final Account account = generateAccount("user.account1@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account);

    accounts.reserveUsernameHash(account, USERNAME_HASH_1, Duration.ofDays(1)).join();
    assertArrayEquals(USERNAME_HASH_1, account.getReservedUsernameHash().orElseThrow());
    assertThat(account.getUsernameHash()).isEmpty();

    accounts.reserveUsernameHash(account, USERNAME_HASH_2, Duration.ofDays(1)).join();
    assertArrayEquals(USERNAME_HASH_2, account.getReservedUsernameHash().orElseThrow());
    assertThat(account.getUsernameHash()).isEmpty();

    final Map<String, AttributeValue> usernameConstraintRecord1 = getUsernameConstraintTableItem(USERNAME_HASH_1);
    final Map<String, AttributeValue> usernameConstraintRecord2 = getUsernameConstraintTableItem(USERNAME_HASH_2);
    assertThat(usernameConstraintRecord1).containsKey(Accounts.UsernameTable.KEY_USERNAME_HASH);
    assertThat(usernameConstraintRecord2).containsKey(Accounts.UsernameTable.KEY_USERNAME_HASH);
    assertThat(usernameConstraintRecord1).containsKey(Accounts.UsernameTable.ATTR_TTL);
    assertThat(usernameConstraintRecord2).containsKey(Accounts.UsernameTable.ATTR_TTL);

    clock.pin(Instant.EPOCH.plus(Duration.ofMinutes(1)));

    accounts.reserveUsernameHash(account, USERNAME_HASH_1, Duration.ofDays(1)).join();
    assertArrayEquals(USERNAME_HASH_1, account.getReservedUsernameHash().orElseThrow());
    assertThat(account.getUsernameHash()).isEmpty();

    final Map<String, AttributeValue> newUsernameConstraintRecord1 = getUsernameConstraintTableItem(USERNAME_HASH_1);
    assertThat(newUsernameConstraintRecord1).containsKey(Accounts.UsernameTable.KEY_USERNAME_HASH);
    assertThat(newUsernameConstraintRecord1).containsKey(Accounts.UsernameTable.ATTR_TTL);
    assertThat(usernameConstraintRecord1.get(Accounts.UsernameTable.ATTR_TTL))
        .isNotEqualTo(newUsernameConstraintRecord1.get(Accounts.UsernameTable.ATTR_TTL));
  }

  @Test
  void reserveOwnConfirmedUsername() {
    final Account account = generateAccount("user.account1@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account);

    accounts.reserveUsernameHash(account, USERNAME_HASH_1, Duration.ofDays(1)).join();
    assertArrayEquals(USERNAME_HASH_1, account.getReservedUsernameHash().orElseThrow());
    assertThat(account.getUsernameHash()).isEmpty();
    assertThat(getUsernameConstraintTableItem(USERNAME_HASH_1)).containsKey(Accounts.UsernameTable.ATTR_TTL);


    accounts.confirmUsernameHash(account, USERNAME_HASH_1, ENCRYPTED_USERNAME_1).join();
    assertThat(account.getReservedUsernameHash()).isEmpty();
    assertArrayEquals(USERNAME_HASH_1, account.getUsernameHash().orElseThrow());
    assertThat(getUsernameConstraintTableItem(USERNAME_HASH_1)).doesNotContainKey(Accounts.UsernameTable.ATTR_TTL);

    CompletableFutureTestUtil.assertFailsWithCause(UsernameHashNotAvailableException.class,
        accounts.reserveUsernameHash(account, USERNAME_HASH_1, Duration.ofDays(1)));
    assertThat(account.getReservedUsernameHash()).isEmpty();
    assertArrayEquals(USERNAME_HASH_1, account.getUsernameHash().orElseThrow());
    assertThat(getUsernameConstraintTableItem(USERNAME_HASH_1)).containsKey(Accounts.UsernameTable.KEY_USERNAME_HASH);
    assertThat(getUsernameConstraintTableItem(USERNAME_HASH_1)).doesNotContainKey(Accounts.UsernameTable.ATTR_TTL);
  }

  @Test
  void testConfirmReservedUsernameHashWrongAccountUuid() {
    final Account account1 = generateAccount("user.account1@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account1);
    final Account account2 = generateAccount("user.account2@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account2);

    accounts.reserveUsernameHash(account1, USERNAME_HASH_1, Duration.ofDays(1)).join();
    assertArrayEquals(USERNAME_HASH_1, account1.getReservedUsernameHash().orElseThrow());
    assertThat(account1.getUsernameHash()).isEmpty();

    // only account1 should be able to confirm the reserved hash
    CompletableFutureTestUtil.assertFailsWithCause(UsernameHashNotAvailableException.class,
        accounts.confirmUsernameHash(account2, USERNAME_HASH_1, ENCRYPTED_USERNAME_1));
  }

  @Test
  void testConfirmExpiredReservedUsernameHash() {
    final Account account1 = generateAccount("user.account1@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account1);
    final Account account2 = generateAccount("user.account2@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account2);

    accounts.reserveUsernameHash(account1, USERNAME_HASH_1, Duration.ofDays(2)).join();

    for (int i = 0; i <= 2; i++) {
      clock.pin(Instant.EPOCH.plus(Duration.ofDays(i)));
      CompletableFutureTestUtil.assertFailsWithCause(UsernameHashNotAvailableException.class,
          accounts.reserveUsernameHash(account2, USERNAME_HASH_1, Duration.ofDays(1)));
    }

    // after 2 days, can reserve and confirm the hash
    clock.pin(Instant.EPOCH.plus(Duration.ofDays(2)).plus(Duration.ofSeconds(1)));
    accounts.reserveUsernameHash(account2, USERNAME_HASH_1, Duration.ofDays(1)).join();
    assertEquals(USERNAME_HASH_1, account2.getReservedUsernameHash().orElseThrow());

    accounts.confirmUsernameHash(account2, USERNAME_HASH_1, ENCRYPTED_USERNAME_1).join();

    CompletableFutureTestUtil.assertFailsWithCause(UsernameHashNotAvailableException.class,
        accounts.reserveUsernameHash(account1, USERNAME_HASH_1, Duration.ofDays(2)));
    CompletableFutureTestUtil.assertFailsWithCause(UsernameHashNotAvailableException.class,
        accounts.confirmUsernameHash(account1, USERNAME_HASH_1, ENCRYPTED_USERNAME_1));
    assertThat(accounts.getByUsernameHash(USERNAME_HASH_1).join().orElseThrow().getUuid()).isEqualTo(account2.getUuid());
  }

  @Test
  void testReserveConfirmUsernameHashVersionConflict() {
    final Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account);
    account.setVersion(account.getVersion() + 12);
    CompletableFutureTestUtil.assertFailsWithCause(ContestedOptimisticLockException.class,
        accounts.reserveUsernameHash(account, USERNAME_HASH_1, Duration.ofDays(1)));
    CompletableFutureTestUtil.assertFailsWithCause(ContestedOptimisticLockException.class,
        accounts.confirmUsernameHash(account, USERNAME_HASH_1, ENCRYPTED_USERNAME_1));
    assertThat(account.getReservedUsernameHash()).isEmpty();
    assertThat(account.getUsernameHash()).isEmpty();
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void testRemoveOldestHold(boolean clearUsername) {
    Account account = generateAccount("user.account1@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account);

    accounts.reserveUsernameHash(account, USERNAME_HASH_1, Duration.ofDays(1)).join();
    accounts.confirmUsernameHash(account, USERNAME_HASH_1, ENCRYPTED_USERNAME_1).join();

    final List<byte[]> usernames = IntStream.range(0, 7).mapToObj(i -> TestRandomUtil.nextBytes(32)).toList();
    final ArrayDeque<byte[]> expectedHolds = new ArrayDeque<>();
    expectedHolds.add(USERNAME_HASH_1);

    for (byte[] username : usernames) {
      accounts.reserveUsernameHash(account, username, Duration.ofDays(1)).join();
      accounts.confirmUsernameHash(account, username, ENCRYPTED_USERNAME_1).join();
      assertThat(accounts.getByUsernameHash(username).join()).isPresent();

      final Account read = accounts.getByAccountIdentifier(account.getUuid()).orElseThrow();
      assertThat(read.getUsernameHolds().stream().map(Account.UsernameHold::usernameHash).toList())
          .containsExactlyElementsOf(expectedHolds);

      expectedHolds.add(username);
      if (expectedHolds.size() == Accounts.MAX_USERNAME_HOLDS + 1) {
        expectedHolds.pop();
      }

      // clearing the username adds a hold, but the subsequent confirm in the next iteration should add the same hold
      // (should be a noop) so we don't need to touch expectedHolds
      if (clearUsername) {
        accounts.clearUsernameHash(account).join();
      }
    }


    final Account account2 = generateAccount("user.account2@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account2);

    // someone else should be able to get any of the usernames except the held usernames (MAX_HOLDS) +1 for the username
    // currently held by the other account if we didn't clear it
    final int numFree = usernames.size() - Accounts.MAX_USERNAME_HOLDS - (clearUsername ? 0 : 1);
    final List<byte[]> freeUsernames = usernames.subList(0, numFree);
    final List<byte[]> heldUsernames = usernames.subList(numFree, usernames.size());
    for (byte[] username : freeUsernames) {
      assertDoesNotThrow(() ->
          accounts.reserveUsernameHash(account2, username, Duration.ofDays(2)).join());
    }
    for (byte[] username : heldUsernames) {
      CompletableFutureTestUtil.assertFailsWithCause(UsernameHashNotAvailableException.class,
          accounts.reserveUsernameHash(account2, username, Duration.ofDays(2)));
    }
  }

  @Test
  void testHoldUsername() {
    final Account account = generateAccount("user.account1@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account);

    accounts.reserveUsernameHash(account, USERNAME_HASH_1, Duration.ofDays(1)).join();
    accounts.confirmUsernameHash(account, USERNAME_HASH_1, ENCRYPTED_USERNAME_1).join();

    accounts.clearUsernameHash(account).join();

    Account account2 = generateAccount("user.account2@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account2);
    CompletableFutureTestUtil.assertFailsWithCause(
        UsernameHashNotAvailableException.class,
        accounts.reserveUsernameHash(account2, USERNAME_HASH_1, Duration.ofDays(1)),
        "account2 should not be able reserve username held by account");

    // but we should be able to get it back
    accounts.reserveUsernameHash(account, USERNAME_HASH_1, Duration.ofDays(1)).join();
    accounts.confirmUsernameHash(account, USERNAME_HASH_1, ENCRYPTED_USERNAME_1).join();
  }

  @Test
  void testNoHoldsBarred() {
    // should be able to reserve all MAX_HOLDS usernames
    final Account account = generateAccount("user.account1@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account);
    final List<byte[]> usernames = IntStream.range(0, Accounts.MAX_USERNAME_HOLDS + 1)
        .mapToObj(i -> TestRandomUtil.nextBytes(32))
        .toList();
    for (byte[] username : usernames) {
      accounts.reserveUsernameHash(account, username, Duration.ofDays(1)).join();
      accounts.confirmUsernameHash(account, username, ENCRYPTED_USERNAME_1).join();
    }

    // someone else shouldn't be able to get any of our holds
    Account account2 = generateAccount("user.account2@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account2);
    for (byte[] username : usernames) {
      CompletableFutureTestUtil.assertFailsWithCause(
          UsernameHashNotAvailableException.class,
          accounts.reserveUsernameHash(account2, username, Duration.ofDays(1)),
          "account2 should not be able reserve username held by account");
    }

    // once the hold expires it's fine though
    clock.pin(Instant.EPOCH.plus(Accounts.USERNAME_HOLD_DURATION).plus(Duration.ofSeconds(1)));
    accounts.reserveUsernameHash(account2, usernames.getFirst(), Duration.ofDays(1)).join();

    // if account1 modifies their username, we should also clear out the old holds, leaving only their newly added hold
    accounts.clearUsernameHash(account).join();
    assertThat(account.getUsernameHolds().stream().map(Account.UsernameHold::usernameHash))
        .containsExactly(usernames.getLast());
  }

  @Test
  public void testCannotRemoveHold() {
    // Tests the case where we are trying to remove a hold we think we have, but it turns out we've already lost it.
    // This means that the Account record an account has a hold on a particular username, but that hold is held by
    // someone else in the username table. This can happen when the hold TTL expires while we are performing the update
    // operation that attempts to remove the hold, and another user swoops in and takes the held username. In this
    // case, a simple retry should let us check the clock again and notice that our hold in our account has expired.
    final Account account = generateAccount("user.account1@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account);
    accounts.reserveUsernameHash(account, USERNAME_HASH_1, Duration.ofDays(1)).join();
    accounts.confirmUsernameHash(account, USERNAME_HASH_1, ENCRYPTED_USERNAME_1).join();

    accounts.reserveUsernameHash(account, USERNAME_HASH_2, Duration.ofDays(1)).join();
    accounts.confirmUsernameHash(account, USERNAME_HASH_2, ENCRYPTED_USERNAME_1).join();

    // Now we have a hold on username_hash_1. Simulate a race where the TTL on username_hash_1 expires, and someone
    // else picks up the username by going forward and then back in time
    Account account2 = generateAccount("user.account2@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account2);
    clock.pin(Instant.EPOCH.plus(Accounts.USERNAME_HOLD_DURATION).plus(Duration.ofSeconds(1)));
    accounts.reserveUsernameHash(account2, USERNAME_HASH_1, Duration.ofDays(1)).join();
    accounts.confirmUsernameHash(account2, USERNAME_HASH_1, ENCRYPTED_USERNAME_1).join();

    clock.pin(Instant.EPOCH);
    // already have 1 hold, should be able to get to MAX_HOLDS without a problem
    for (int i = 1; i < Accounts.MAX_USERNAME_HOLDS; i++) {
      accounts.reserveUsernameHash(account, TestRandomUtil.nextBytes(32), Duration.ofDays(1)).join();
      accounts.confirmUsernameHash(account, TestRandomUtil.nextBytes(32), ENCRYPTED_USERNAME_1).join();
    }

    accounts.reserveUsernameHash(account, TestRandomUtil.nextBytes(32), Duration.ofDays(1)).join();
    // Should fail, because we cannot remove our hold on USERNAME_HASH_1
    CompletableFutureTestUtil.assertFailsWithCause(ContestedOptimisticLockException.class,
        accounts.confirmUsernameHash(account, TestRandomUtil.nextBytes(32), ENCRYPTED_USERNAME_1));

    // Should now pass once we realize our hold's TTL is over
    clock.pin(Instant.EPOCH.plus(Accounts.USERNAME_HOLD_DURATION).plus(Duration.ofSeconds(1)));
    accounts.confirmUsernameHash(account, TestRandomUtil.nextBytes(32), ENCRYPTED_USERNAME_1).join();
  }

  @Test
  void testDeduplicateHoldsOnSwappedUsernames() {
    final Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account);

    accounts.reserveUsernameHash(account, USERNAME_HASH_1, Duration.ofDays(1)).join();
    accounts.confirmUsernameHash(account, USERNAME_HASH_1, ENCRYPTED_USERNAME_1).join();

    final Consumer<byte[]> assertSingleHold = (byte[] usernameToCheck) -> {
      // our account should have exactly one hold for the username
      assertThat(account.getUsernameHolds().stream().map(Account.UsernameHold::usernameHash).toList())
          .containsExactly(usernameToCheck);

      // the username should be reserved for USERNAME_HOLD_DURATION (a re-reservation shouldn't reduce our expiration to
      // the provided reservation TTL)
      assertThat(
          AttributeValues.getLong(getUsernameConstraintTableItem(usernameToCheck), Accounts.UsernameTable.ATTR_TTL, 0L))
          .isEqualTo(Accounts.USERNAME_HOLD_DURATION.getSeconds());
    };

    // Swap back and forth between username 1 and 2.  Username hashes shouldn't reappear in our holds if we already have
    // a hold
    for (int i = 0; i < 5; i++) {
      accounts.reserveUsernameHash(account, USERNAME_HASH_2, Duration.ofSeconds(1)).join();
      accounts.confirmUsernameHash(account, USERNAME_HASH_2, ENCRYPTED_USERNAME_1).join();
      assertSingleHold.accept(USERNAME_HASH_1);

      accounts.reserveUsernameHash(account, USERNAME_HASH_1, Duration.ofSeconds(1)).join();
      accounts.confirmUsernameHash(account, USERNAME_HASH_1, ENCRYPTED_USERNAME_1).join();
      assertSingleHold.accept(USERNAME_HASH_2);
    }
  }

  @Test
  void testRemoveHoldAfterConfirm() {
    final Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account);
    final List<byte[]> usernames = IntStream.range(0, Accounts.MAX_USERNAME_HOLDS)
        .mapToObj(i -> TestRandomUtil.nextBytes(32)).toList();
    for (byte[] username : usernames) {
      accounts.reserveUsernameHash(account, username, Duration.ofDays(1)).join();
      accounts.confirmUsernameHash(account, username, ENCRYPTED_USERNAME_1).join();
    }

    int holdToRereserve = (Accounts.MAX_USERNAME_HOLDS / 2) - 1;

    // should have MAX_HOLDS - 1 holds (everything in usernames except the last username, which is our current)
    assertThat(account.getUsernameHolds().stream().map(Account.UsernameHold::usernameHash).toList())
        .containsExactlyElementsOf(usernames.subList(0, usernames.size() - 1));

    // if we confirm a username we already have held, it should just drop out of the holds list
    accounts.reserveUsernameHash(account, usernames.get(holdToRereserve), Duration.ofDays(1)).join();
    accounts.confirmUsernameHash(account, usernames.get(holdToRereserve), ENCRYPTED_USERNAME_1).join();

    // should have a hold on every username but the one we just confirmed
    assertThat(account.getUsernameHolds().stream().map(Account.UsernameHold::usernameHash).toList())
        .containsExactlyElementsOf(Stream.concat(
                usernames.subList(0, holdToRereserve).stream(),
                usernames.subList(holdToRereserve + 1, usernames.size()).stream())
            .toList());
  }


  @Test
  public void testIgnoredFieldsNotAddedToDataAttribute() throws Exception {
    final Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID());
    account.setUsernameHash(TestRandomUtil.nextBytes(32));
    account.setUsernameLinkDetails(UUID.randomUUID(), TestRandomUtil.nextBytes(32));
    createAccount(account);
    final Map<String, AttributeValue> accountRecord = DYNAMO_DB_EXTENSION.getDynamoDbClient()
        .getItem(GetItemRequest.builder()
            .tableName(Tables.ACCOUNTS.tableName())
            .key(Map.of(Accounts.KEY_ACCOUNT_UUID, AttributeValues.fromUUID(account.getUuid())))
            .build())
        .item();
    final Map<?, ?> dataMap = SystemMapper.jsonMapper()
        .readValue(accountRecord.get(Accounts.ATTR_ACCOUNT_DATA).b().asByteArray(), Map.class);
    Accounts.ACCOUNT_FIELDS_TO_EXCLUDE_FROM_SERIALIZATION
        .forEach(field -> assertFalse(dataMap.containsKey(field)));
  }

  @Test
  void testGetByUsernameHashAsync() {
    assertThat(accounts.getByUsernameHash(USERNAME_HASH_1).join()).isEmpty();

    final Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID());
    createAccount(account);

    assertThat(accounts.getByUsernameHash(USERNAME_HASH_1).join()).isEmpty();

    accounts.reserveUsernameHash(account, USERNAME_HASH_1, Duration.ofDays(1)).join();
    accounts.confirmUsernameHash(account, USERNAME_HASH_1, ENCRYPTED_USERNAME_1).join();

    assertThat(accounts.getByUsernameHash(USERNAME_HASH_1).join()).isPresent();
  }

  @Test
  void testInvalidDeviceIdDeserialization() throws Exception {
    final Account account = generateAccount("user.account@example.com", UUID.randomUUID(), UUID.randomUUID());
    final Device device2 = generateDevice((byte) 64);
    account.addDevice(device2);

    createAccount(account);

    final GetItemResponse response = DYNAMO_DB_EXTENSION.getDynamoDbAsyncClient().getItem(GetItemRequest.builder()
        .tableName(Tables.ACCOUNTS.tableName())
        .key(Map.of(Accounts.KEY_ACCOUNT_UUID, AttributeValues.fromUUID(account.getUuid())))
        .build()).join();

    final Map<?, ?> accountData = SystemMapper.jsonMapper()
        .readValue(response.item().get(Accounts.ATTR_ACCOUNT_DATA).b().asByteArray(), Map.class);

    @SuppressWarnings("unchecked") final List<Map<Object, Object>> devices =
        (List<Map<Object, Object>>) accountData.get("devices");

    assertEquals((int) device2.getId(), devices.get(1).get("id"));

    devices.get(1).put("id", Byte.MAX_VALUE + 5);

    DYNAMO_DB_EXTENSION.getDynamoDbAsyncClient().updateItem(UpdateItemRequest.builder()
        .tableName(Tables.ACCOUNTS.tableName())
        .key(Map.of(Accounts.KEY_ACCOUNT_UUID, AttributeValues.fromUUID(account.getUuid())))
        .updateExpression("SET #data = :data")
        .expressionAttributeNames(Map.of("#data", Accounts.ATTR_ACCOUNT_DATA))
        .expressionAttributeValues(
            Map.of(":data", AttributeValues.fromByteArray(SystemMapper.jsonMapper().writeValueAsBytes(accountData))))
        .build()).join();

    final CompletionException e = assertThrows(CompletionException.class,
        () -> accounts.getByAccountIdentifierAsync(account.getUuid()).join());

    Throwable cause = e.getCause();
    while (cause.getCause() != null) {
      cause = cause.getCause();
    }

    assertInstanceOf(DeviceIdDeserializer.DeviceIdDeserializationException.class, cause);
  }

  @Test
  void testRegenerateConstraints() {
    final Instant usernameHoldExpiration = clock.instant().plus(Accounts.USERNAME_HOLD_DURATION).truncatedTo(ChronoUnit.SECONDS);

    final Account account = nextRandomAccount();
    account.setUsernameHash(USERNAME_HASH_1);
    account.setUsernameLinkDetails(UUID.randomUUID(), ENCRYPTED_USERNAME_1);
    account.setUsernameHolds(List.of(new Account.UsernameHold(USERNAME_HASH_2, usernameHoldExpiration.getEpochSecond())));

    writeAccountRecordWithoutConstraints(account);
    accounts.regenerateConstraints(account).join();

    // Check that constraints do what they should from a functional perspective
    {
      final Account conflictingPrincipalAccount = nextRandomAccount();
      conflictingPrincipalAccount.setPrincipal(account.getPrincipal(), account.getIdentifier(IdentityType.PNI));

      assertThrows(AccountAlreadyExistsException.class,
          () -> accounts.create(conflictingPrincipalAccount, new PrincipalVerificationDetails(
              PrincipalVerificationDetails.VerificationType.SESSION,
                  "provider-example", "subject-example", conflictingPrincipalAccount.getPrincipal()),
              Collections.emptyList()));
    }

    {
      final Account conflictingUsernameAccount = nextRandomAccount();
      createAccount(conflictingUsernameAccount);

      final CompletionException completionException = assertThrows(CompletionException.class,
          () -> accounts.reserveUsernameHash(conflictingUsernameAccount, USERNAME_HASH_1, Accounts.USERNAME_HOLD_DURATION).join());

      assertInstanceOf(UsernameHashNotAvailableException.class, completionException.getCause());
    }

    {
      final Account conflictingUsernameHoldAccount = nextRandomAccount();
      createAccount(conflictingUsernameHoldAccount);

      final CompletionException completionException = assertThrows(CompletionException.class,
          () -> accounts.reserveUsernameHash(conflictingUsernameHoldAccount, USERNAME_HASH_2, Accounts.USERNAME_HOLD_DURATION).join());

      assertInstanceOf(UsernameHashNotAvailableException.class, completionException.getCause());
    }

    // Check that bare constraint records are written as expected
    assertEquals(Optional.of(account.getIdentifier(IdentityType.ACI)),
        getConstraintValue(Tables.PRINCIPALS.tableName(), Accounts.ATTR_ACCOUNT_PRINCIPAL, AttributeValues.fromString(account.getPrincipal())));

    assertEquals(Optional.of(account.getIdentifier(IdentityType.ACI)),
        getConstraintValue(Tables.PNI_ASSIGNMENTS.tableName(), Accounts.ATTR_PNI_UUID, AttributeValues.fromUUID(account.getIdentifier(IdentityType.PNI))));

    assertEquals(Optional.of(new UsernameConstraint(account.getIdentifier(IdentityType.ACI), true, Optional.empty())),
        getUsernameConstraint(USERNAME_HASH_1));

    assertEquals(Optional.of(new UsernameConstraint(account.getIdentifier(IdentityType.ACI), false, Optional.of(usernameHoldExpiration))),
        getUsernameConstraint(USERNAME_HASH_2));
  }

  @Test
  void testRegeneratedConstraintsMatchOriginalConstraints() {
    final Instant usernameHoldExpiration = clock.instant().plus(Accounts.USERNAME_HOLD_DURATION).truncatedTo(ChronoUnit.SECONDS);

    final Account account = nextRandomAccount();
    account.setUsernameHash(USERNAME_HASH_1);
    account.setUsernameLinkDetails(UUID.randomUUID(), ENCRYPTED_USERNAME_1);
    account.setUsernameHolds(List.of(new Account.UsernameHold(USERNAME_HASH_2, usernameHoldExpiration.getEpochSecond())));

    createAccount(account);
    accounts.reserveUsernameHash(account, USERNAME_HASH_2, Accounts.USERNAME_HOLD_DURATION).join();
    accounts.confirmUsernameHash(account, USERNAME_HASH_2, ENCRYPTED_USERNAME_2).join();
    accounts.reserveUsernameHash(account, USERNAME_HASH_1, Accounts.USERNAME_HOLD_DURATION).join();
    accounts.confirmUsernameHash(account, USERNAME_HASH_1, ENCRYPTED_USERNAME_1).join();

    final Map<String, AttributeValue> originalPrincipalConstraintItem =
        DYNAMO_DB_EXTENSION.getDynamoDbClient().getItem(GetItemRequest.builder()
                .tableName(Tables.PRINCIPALS.tableName())
                .key(Map.of(Accounts.ATTR_ACCOUNT_PRINCIPAL, AttributeValues.fromString(account.getPrincipal())))
                .build())
            .item();

    final Map<String, AttributeValue> originalPniConstraintItem =
        DYNAMO_DB_EXTENSION.getDynamoDbClient().getItem(GetItemRequest.builder()
                .tableName(Tables.PNI_ASSIGNMENTS.tableName())
                .key(Map.of(Accounts.ATTR_PNI_UUID, AttributeValues.fromUUID(account.getIdentifier(IdentityType.PNI))))
                .build())
            .item();

    final Set<Map<String, AttributeValue>> originalUsernameConstraints = new HashSet<>(
        DYNAMO_DB_EXTENSION.getDynamoDbClient().scan(ScanRequest.builder()
                .tableName(Tables.USERNAMES.tableName())
                .build())
            .items());

    accounts.delete(account.getIdentifier(IdentityType.ACI), Collections.emptyList()).join();

    writeAccountRecordWithoutConstraints(account);
    accounts.regenerateConstraints(account).join();

    final Map<String, AttributeValue> regeneratedPrincipalConstraintItem =
        DYNAMO_DB_EXTENSION.getDynamoDbClient().getItem(GetItemRequest.builder()
                .tableName(Tables.PRINCIPALS.tableName())
                .key(Map.of(Accounts.ATTR_ACCOUNT_PRINCIPAL, AttributeValues.fromString(account.getPrincipal())))
                .build())
            .item();

    final Map<String, AttributeValue> regeneratedPniConstraintItem =
        DYNAMO_DB_EXTENSION.getDynamoDbClient().getItem(GetItemRequest.builder()
                .tableName(Tables.PNI_ASSIGNMENTS.tableName())
                .key(Map.of(Accounts.ATTR_PNI_UUID, AttributeValues.fromUUID(account.getIdentifier(IdentityType.PNI))))
                .build())
            .item();

    final Set<Map<String, AttributeValue>> regeneratedUsernameConstraints = new HashSet<>(
        DYNAMO_DB_EXTENSION.getDynamoDbClient().scan(ScanRequest.builder()
                .tableName(Tables.USERNAMES.tableName())
                .build())
            .items());

    assertEquals(originalPrincipalConstraintItem, regeneratedPrincipalConstraintItem);
    assertEquals(originalPniConstraintItem, regeneratedPniConstraintItem);
    assertEquals(originalUsernameConstraints, regeneratedUsernameConstraints);
  }

  private void writeAccountRecordWithoutConstraints(final Account account) {
    final AttributeValue accountData;

    try {
      accountData = AttributeValues.fromByteArray(Accounts.ACCOUNT_DDB_JSON_WRITER.writeValueAsBytes(account));
    } catch (final JsonProcessingException e) {
      throw new IllegalArgumentException(e);
    }

    final Map<String, AttributeValue> item = new HashMap<>(Map.of(
        Accounts.KEY_ACCOUNT_UUID, AttributeValues.fromUUID(account.getUuid()),
        Accounts.ATTR_ACCOUNT_PRINCIPAL, AttributeValues.fromString(account.getPrincipal()),
        Accounts.ATTR_PNI_UUID, AttributeValues.fromUUID(account.getPrincipalNameIdentifier()),
        Accounts.ATTR_ACCOUNT_DATA, accountData,
        Accounts.ATTR_VERSION, AttributeValues.fromInt(account.getVersion()),
        Accounts.ATTR_CANONICALLY_DISCOVERABLE, AttributeValues.fromBool(account.isDiscoverableByPrincipal())));

    account.getUnidentifiedAccessKey()
        .map(AttributeValues::fromByteArray)
        .ifPresent(uak -> item.put(Accounts.ATTR_UAK, uak));

    DYNAMO_DB_EXTENSION.getDynamoDbClient().putItem(PutItemRequest.builder()
            .tableName(Tables.ACCOUNTS.tableName())
            .item(item)
        .build());
  }

  private Optional<UUID> getConstraintValue(final String tableName,
      final String keyName,
      final AttributeValue keyValue) {

    final GetItemResponse response = DYNAMO_DB_EXTENSION.getDynamoDbClient().getItem(GetItemRequest.builder()
            .tableName(tableName)
            .key(Map.of(keyName, keyValue))
        .build());

    return response.hasItem()
        ? Optional.ofNullable(AttributeValues.getUUID(response.item(), Accounts.KEY_ACCOUNT_UUID, null))
        : Optional.empty();
  }

  private Optional<UsernameConstraint> getUsernameConstraint(final byte[] usernameHash) {
    final GetItemResponse response = DYNAMO_DB_EXTENSION.getDynamoDbClient().getItem(GetItemRequest.builder()
            .tableName(Tables.USERNAMES.tableName())
            .key(Map.of(Accounts.UsernameTable.KEY_USERNAME_HASH, AttributeValues.fromByteArray(usernameHash)))
        .build());

    if (response.hasItem()) {
      final UUID accountIdentifier =
          AttributeValues.getUUID(response.item(), Accounts.UsernameTable.ATTR_ACCOUNT_UUID, null);

      final boolean confirmed = AttributeValues.getBool(response.item(), Accounts.UsernameTable.ATTR_CONFIRMED, false);

      final Optional<Instant> expiration = response.item().containsKey(Accounts.UsernameTable.ATTR_TTL)
          ? Optional.of(Instant.ofEpochSecond(AttributeValues.getLong(response.item(), Accounts.UsernameTable.ATTR_TTL, 0)))
          : Optional.empty();

      return Optional.of(new UsernameConstraint(accountIdentifier, confirmed, expiration));
    }

    return Optional.empty();
  }

  private static Device generateDevice(byte id) {
    return DevicesHelper.createDevice(id);
  }

  private boolean createAccount(final Account account) {
    try {
      return accounts.create(account, new PrincipalVerificationDetails(PrincipalVerificationDetails.VerificationType.SESSION,
          "provider-example", "subject-example", account.getPrincipal()), Collections.emptyList());
    } catch (AccountAlreadyExistsException e) {
      throw new IllegalStateException(e);
    }
  }

  private static Account nextRandomAccount() {
    final String nextPrincipal = "user.account.%03d@example.com".formatted(ACCOUNT_COUNTER.getAndIncrement());
    return generateAccount(nextPrincipal, UUID.randomUUID(), UUID.randomUUID());
  }

  private static Account generateAccount(String principal, UUID uuid, final UUID pni) {
    Device device = generateDevice(DEVICE_ID_1);
    return generateAccount(principal, uuid, pni, List.of(device));
  }

  private static Account generateAccount(String principal, UUID uuid, final UUID pni, List<Device> devices) {
    final byte[] unidentifiedAccessKey = new byte[UnidentifiedAccessUtil.UNIDENTIFIED_ACCESS_KEY_LENGTH];
    final Random random = new Random(System.currentTimeMillis());
    Arrays.fill(unidentifiedAccessKey, (byte) random.nextInt(255));

    return AccountsHelper.generateTestAccount(principal, uuid, pni, devices, unidentifiedAccessKey);
  }

  private void assertPrincipalConstraintExists(final String principal, final UUID uuid) {
    final GetItemResponse principalConstraintResponse = DYNAMO_DB_EXTENSION.getDynamoDbClient().getItem(
        GetItemRequest.builder()
            .tableName(Tables.PRINCIPALS.tableName())
            .key(Map.of(Accounts.ATTR_ACCOUNT_PRINCIPAL, AttributeValues.fromString(principal)))
            .build());

    assertThat(principalConstraintResponse.hasItem()).isTrue();
    assertThat(AttributeValues.getUUID(principalConstraintResponse.item(), Accounts.KEY_ACCOUNT_UUID, null)).isEqualTo(uuid);
  }

  private void assertPrincipalConstraintDoesNotExist(final String principal) {
    final GetItemResponse principalConstraintResponse = DYNAMO_DB_EXTENSION.getDynamoDbClient().getItem(
        GetItemRequest.builder()
            .tableName(Tables.PRINCIPALS.tableName())
            .key(Map.of(Accounts.ATTR_ACCOUNT_PRINCIPAL, AttributeValues.fromString(principal)))
            .build());

    assertThat(principalConstraintResponse.hasItem()).isFalse();
  }

  private void assertPrincipalNameIdentifierConstraintExists(final UUID principalNameIdentifier, final UUID uuid) {
    final GetItemResponse pniConstraintResponse = DYNAMO_DB_EXTENSION.getDynamoDbClient().getItem(
        GetItemRequest.builder()
            .tableName(Tables.PNI_ASSIGNMENTS.tableName())
            .key(Map.of(Accounts.ATTR_PNI_UUID, AttributeValues.fromUUID(principalNameIdentifier)))
            .build());

    assertThat(pniConstraintResponse.hasItem()).isTrue();
    assertThat(AttributeValues.getUUID(pniConstraintResponse.item(), Accounts.KEY_ACCOUNT_UUID, null)).isEqualTo(uuid);
  }

  private void assertPrincipalNameIdentifierConstraintDoesNotExist(final UUID principalNameIdentifier) {
    final GetItemResponse pniConstraintResponse = DYNAMO_DB_EXTENSION.getDynamoDbClient().getItem(
        GetItemRequest.builder()
            .tableName(Tables.PNI_ASSIGNMENTS.tableName())
            .key(Map.of(Accounts.ATTR_PNI_UUID, AttributeValues.fromUUID(principalNameIdentifier)))
            .build());

    assertThat(pniConstraintResponse.hasItem()).isFalse();
  }

  private Map<String, AttributeValue> readAccount(final UUID uuid) {
    final DynamoDbClient db = DYNAMO_DB_EXTENSION.getDynamoDbClient();

    final GetItemResponse get = db.getItem(GetItemRequest.builder()
        .tableName(Tables.ACCOUNTS.tableName())
        .key(Map.of(Accounts.KEY_ACCOUNT_UUID, AttributeValues.fromUUID(uuid)))
        .consistentRead(true)
        .build());
    return get.item();
  }

  private Map<String, AttributeValue> getUsernameConstraintTableItem(final byte[] usernameHash) {
    return DYNAMO_DB_EXTENSION.getDynamoDbClient()
        .getItem(GetItemRequest.builder()
            .tableName(Tables.USERNAMES.tableName())
            .key(Map.of(Accounts.UsernameTable.KEY_USERNAME_HASH, AttributeValues.fromByteArray(usernameHash)))
            .build())
        .item();
  }

  @SuppressWarnings("SameParameterValue")
  private void verifyStoredState(String principal, UUID uuid, UUID pni, byte[] usernameHash, Account expecting, boolean canonicallyDiscoverable) {
    final DynamoDbClient db = DYNAMO_DB_EXTENSION.getDynamoDbClient();

    final GetItemResponse get = db.getItem(GetItemRequest.builder()
        .tableName(Tables.ACCOUNTS.tableName())
        .key(Map.of(Accounts.KEY_ACCOUNT_UUID, AttributeValues.fromUUID(uuid)))
        .consistentRead(true)
        .build());

    if (get.hasItem()) {
      String data = new String(get.item().get(Accounts.ATTR_ACCOUNT_DATA).b().asByteArray(), StandardCharsets.UTF_8);
      assertThat(data).isNotEmpty();

      assertThat(AttributeValues.getInt(get.item(), Accounts.ATTR_VERSION, -1))
          .isEqualTo(expecting.getVersion());

      assertThat(AttributeValues.getBool(get.item(), Accounts.ATTR_CANONICALLY_DISCOVERABLE,
          !canonicallyDiscoverable)).isEqualTo(canonicallyDiscoverable);

      assertThat(AttributeValues.getByteArray(get.item(), Accounts.ATTR_UAK, null))
          .isEqualTo(expecting.getUnidentifiedAccessKey().orElse(null));

      assertArrayEquals(AttributeValues.getByteArray(get.item(), Accounts.ATTR_USERNAME_HASH, null), usernameHash);

      Account result = Accounts.fromItem(get.item());
      verifyStoredState(principal, uuid, pni, usernameHash, result, expecting);
    } else {
      throw new AssertionError("No data");
    }
  }

  private void verifyStoredState(String principal, UUID uuid, UUID pni, byte[] usernameHash, Account result, Account expecting) {
    assertThat(result.getPrincipal()).isEqualTo(principal);
    assertThat(result.getPrincipalNameIdentifier()).isEqualTo(pni);
    assertThat(result.getLastSeen()).isEqualTo(expecting.getLastSeen());
    assertThat(result.getUuid()).isEqualTo(uuid);
    assertThat(result.getVersion()).isEqualTo(expecting.getVersion());
    assertArrayEquals(result.getUsernameHash().orElse(null), usernameHash);
    assertArrayEquals(expecting.getUnidentifiedAccessKey().orElseThrow(), result.getUnidentifiedAccessKey().orElseThrow());

    for (final Device expectingDevice : expecting.getDevices()) {
      final Device resultDevice = result.getDevice(expectingDevice.getId()).orElseThrow();
      assertThat(resultDevice.getApnId()).isEqualTo(expectingDevice.getApnId());
      assertThat(resultDevice.getGcmId()).isEqualTo(expectingDevice.getGcmId());
      assertThat(resultDevice.getLastSeen()).isEqualTo(expectingDevice.getLastSeen());
      assertThat(resultDevice.getFetchesMessages()).isEqualTo(expectingDevice.getFetchesMessages());
      assertThat(resultDevice.getUserAgent()).isEqualTo(expectingDevice.getUserAgent());
      assertThat(resultDevice.getName()).isEqualTo(expectingDevice.getName());
      assertThat(resultDevice.getCreated()).isEqualTo(expectingDevice.getCreated());
    }
  }
}
