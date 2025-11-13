/*
 * Copyright 2013-2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import com.google.common.annotations.VisibleForTesting;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Timer;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.identity.IdentityType;
import org.whispersystems.textsecuregcm.util.AttributeValues;
import org.whispersystems.textsecuregcm.util.ExceptionUtils;
import org.whispersystems.textsecuregcm.util.Util;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.model.BatchGetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.CancellationReason;
import software.amazon.awssdk.services.dynamodb.model.KeysAndAttributes;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.ReturnValuesOnConditionCheckFailure;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItem;
import software.amazon.awssdk.services.dynamodb.model.TransactWriteItemsRequest;
import software.amazon.awssdk.services.dynamodb.model.TransactionCanceledException;
import software.amazon.awssdk.services.dynamodb.model.TransactionConflictException;
import software.amazon.awssdk.services.dynamodb.model.Update;

/**
 * Manages a global, persistent mapping of principals to principal name identifiers regardless of whether those
 * numbers/identifiers are actually associated with an account.
 */
public class PrincipalNameIdentifiers {

  private final DynamoDbAsyncClient dynamoDbClient;
  private final String tableName;

  @VisibleForTesting
  static final String KEY_PRINCIPAL = "P";
  @VisibleForTesting
  static final String INDEX_NAME = "pni_to_p";
  @VisibleForTesting
  static final String ATTR_PRINCIPAL_NAME_IDENTIFIER = "PNI";

  private static final String CONDITIONAL_CHECK_FAILED = "ConditionalCheckFailed";

  private static final Timer GET_PNI_TIMER = Metrics.timer(name(PrincipalNameIdentifiers.class, "get"));
  private static final Timer SET_PNI_TIMER = Metrics.timer(name(PrincipalNameIdentifiers.class, "set"));
  private static final int MAX_RETRIES = 10;

  private static final Logger logger = LoggerFactory.getLogger(PrincipalNameIdentifiers.class);

  public PrincipalNameIdentifiers(final DynamoDbAsyncClient dynamoDbClient, final String tableName) {
    this.dynamoDbClient = dynamoDbClient;
    this.tableName = tableName;
  }

  /**
   * Returns the principal name identifier (PNI) associated with the given principal. If one doesn't exist, it is
   * created.
   *
   * @param principal the principal for which to retrieve a principal name identifier
   * @return the principal name identifier associated with the given phone number
   */
  public CompletableFuture<UUID> getPrincipalNameIdentifier(final String principal) {
    // Each principal string represents a potential equivalence class that represent the same principal. If
    // this is a new principal, we'll want to set all the principals in the equivalence class to the same PNI
    final List<String> allPrincipalForms = Util.getAlternateForms(principal);

    return retry(MAX_RETRIES, TransactionConflictException.class, () -> fetchPrincipals(allPrincipalForms)
        .thenCompose(mappings -> setPniIfRequired(principal, allPrincipalForms, mappings)));
  }

  /**
   * Returns the list of principals associated with a given principal name identifier. If this
   * UUID was not previously assigned as a PNI by {@link #getPrincipalNameIdentifier(String)}, the
   * returned list will be empty.
   *
   * @param principalNameIdentifier a principal name identifier
   * @return the list of all principals associated with the given principal name identifier
   */
  public CompletableFuture<List<String>> getPrincipal(final UUID principalNameIdentifier) {
    return dynamoDbClient.query(QueryRequest.builder()
            .tableName(tableName)
            .indexName(INDEX_NAME)
            .keyConditionExpression("#pni = :pni")
            .projectionExpression("#principal")
            .expressionAttributeNames(Map.of(
                "#principal", KEY_PRINCIPAL,
                "#pni", ATTR_PRINCIPAL_NAME_IDENTIFIER
            ))
            .expressionAttributeValues(Map.of(
                ":pni", AttributeValues.fromUUID(principalNameIdentifier)
            ))
            .build())
        .thenApply(response -> response.items().stream().map(item -> item.get(KEY_PRINCIPAL).s()).toList());
  }

  @VisibleForTesting
  static <T, E extends Exception> CompletableFuture<T> retry(
      final int numRetries, final Class<E> exceptionToRetry, final Supplier<CompletableFuture<T>> supplier) {
    return supplier.get().exceptionallyCompose(ExceptionUtils.exceptionallyHandler(exceptionToRetry, e -> {
      if (numRetries - 1 <= 0) {
        throw ExceptionUtils.wrap(e);
      }
      return retry(numRetries - 1, exceptionToRetry, supplier);
    }));
  }

  /**
   * Determine what PNI to set for the provided principals, and set them if required
   *
   * @param principal            The original principal the operation is for
   * @param allPrincipalForms    The principals to set. The first element in this list should be principal
   * @param existingAssociations The current associations of allPrincipalForms in the table
   * @return The PNI now associated with principal
   */
  @VisibleForTesting
  CompletableFuture<UUID> setPniIfRequired(
      final String principal,
      final List<String> allPrincipalForms,
      Map<String, UUID> existingAssociations) {
    if (!principal.equals(allPrincipalForms.getFirst())) {
      throw new IllegalArgumentException("allPrincipalForms must start with the target principal");
    }

    if (existingAssociations.containsKey(principal)) {
      // If the provided phone number already has an association, just return that
      return CompletableFuture.completedFuture(existingAssociations.get(principal));
    }

    if (allPrincipalForms.size() == 1 || existingAssociations.isEmpty()) {
      // Easy case, if we're the only phone number in our equivalence class or there are no existing associations,
      // we can just make an association for a new PNI
      return setPni(principal, allPrincipalForms, UUID.randomUUID());
    }

    // Otherwise, what members of the equivalence class have a PNI association?
    final Map<UUID, List<String>> byPni = existingAssociations.entrySet().stream().collect(Collectors.groupingBy(
        Map.Entry::getValue,
        Collectors.mapping(Map.Entry::getKey, Collectors.toList())));

    // Usually there should be only a single PNI associated with the equivalence class, but it's possible there's
    // more. This could only happen if an equivalence class had more than two numbers, and had accumulated 2 unique
    // PNI associations before they were merged into a single class. In this case we've picked one of those pnis
    // arbitrarily (according to their ordering as returned by getAlternateForms)
    final UUID existingPni = allPrincipalForms.stream()
        .filter(existingAssociations::containsKey)
        .findFirst()
        .map(existingAssociations::get)
        .orElseThrow(() -> new IllegalStateException("Previously checked that a mapping existed"));

    if (byPni.size() > 1) {
      logger.warn("More than one PNI existed in the PNI table for the numbers that map to {}. " +
              "Arbitrarily picking {} to be the representative PNI for the numbers without PNI associations",
          principal, existingPni);
    }

    // Find all the unmapped phoneNumbers and set them to the PNI we chose from another member of the equivalence class
    final List<String> unmappedNumbers = allPrincipalForms.stream()
        .filter(number -> !existingAssociations.containsKey(number))
        .toList();

    return setPni(principal, unmappedNumbers, existingPni);
  }


  /**
   * Attempt to associate principals with the provided pni. If any of the principals have an existing association
   * that is not the target pni, no update will occur. If the first principal in principals has an existing
   * association, it will be returned, otherwise an exception will be thrown.
   *
   * @param originalPrincipal The original principal the operation is for
   * @param allPrincipalForms The principals to set. The first principal in this list should be originalPrincipal
   * @param pni                 The PNI to set
   * @return The provided PNI if the update occurred, or the existing PNI associated with originalPrincipal
   */
  @VisibleForTesting
  CompletableFuture<UUID> setPni(final String originalPrincipal, final List<String> allPrincipalForms,
      final UUID pni) {
    if (!originalPrincipal.equals(allPrincipalForms.getFirst())) {
      throw new IllegalArgumentException("allPrincipalForms must start with the target phoneNumber");
    }

    final Timer.Sample sample = Timer.start();
    final List<TransactWriteItem> transactWriteItems = allPrincipalForms
        .stream()
        .map(phoneNumber -> TransactWriteItem.builder()
            .update(Update.builder()
                .tableName(tableName)
                .key(Map.of(KEY_PRINCIPAL, AttributeValues.fromString(phoneNumber)))
                .updateExpression("SET #pni = :pni")
                // It's possible we're racing with someone else to update, but both of us selected the same PNI because
                // an equivalent number already had it. That's fine, as long as the association happens.
                .conditionExpression("attribute_not_exists(#pni) OR #pni = :pni")
                .expressionAttributeNames(Map.of("#pni", ATTR_PRINCIPAL_NAME_IDENTIFIER))
                .expressionAttributeValues(Map.of(":pni", AttributeValues.fromUUID(pni)))
                .returnValuesOnConditionCheckFailure(ReturnValuesOnConditionCheckFailure.ALL_OLD)
                .build()).build())
        .toList();

    return dynamoDbClient.transactWriteItems(TransactWriteItemsRequest.builder()
            .transactItems(transactWriteItems)
            .build())
        .thenApply(ignored -> pni)
        .exceptionally(ExceptionUtils.exceptionallyHandler(TransactionCanceledException.class, e -> {
          if (e.hasCancellationReasons()) {
            // Get the cancellation reason for the number that we were primarily trying to associate with a PNI
            final CancellationReason cancelReason = e.cancellationReasons().getFirst();
            if (CONDITIONAL_CHECK_FAILED.equals(cancelReason.code())) {
              // Someone else beat us to the update, use the PNI they set.
              return AttributeValues.getUUID(cancelReason.item(), ATTR_PRINCIPAL_NAME_IDENTIFIER, null);
            }
          }
          throw e;
        }))
        .whenComplete((ignored, throwable) -> sample.stop(SET_PNI_TIMER));
  }

  @VisibleForTesting
  CompletableFuture<Map<String, UUID>> fetchPrincipals(List<String> principals) {
    final Timer.Sample sample = Timer.start();
    return dynamoDbClient.batchGetItem(
            BatchGetItemRequest.builder().requestItems(Map.of(tableName, KeysAndAttributes.builder()
                    // If we have a stale value, the subsequent conditional update will fail
                    .consistentRead(false)
                    .projectionExpression("#principal,#pni")
                    .expressionAttributeNames(Map.of("#principal", KEY_PRINCIPAL, "#pni", ATTR_PRINCIPAL_NAME_IDENTIFIER))
                    .keys(principals.stream()
                        .map(principal -> Map.of(KEY_PRINCIPAL, AttributeValues.fromString(principal)))
                        .toArray(Map[]::new))
                    .build()))
                .build())
        .thenApply(batchResponse -> batchResponse.responses().get(tableName).stream().collect(Collectors.toMap(
            item -> AttributeValues.getString(item, KEY_PRINCIPAL, null),
            item -> AttributeValues.getUUID(item, ATTR_PRINCIPAL_NAME_IDENTIFIER, null))))
        .whenComplete((ignored, throwable) -> sample.stop(GET_PNI_TIMER));
  }

  CompletableFuture<Void> regeneratePhoneNumberIdentifierMappings(final Account account) {
    return setPni(account.getPrincipal(), Util.getAlternateForms(account.getPrincipal()), account.getIdentifier(IdentityType.PNI))
        .thenRun(Util.NOOP);
  }
}
