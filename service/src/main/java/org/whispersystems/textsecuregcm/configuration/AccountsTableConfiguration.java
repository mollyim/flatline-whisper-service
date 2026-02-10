package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import org.whispersystems.textsecuregcm.configuration.DynamoDbTables.Table;

public class AccountsTableConfiguration extends Table {

  private final String principalTableName;
  private final String principalNameIdentifierTableName;
  private final String usernamesTableName;
  private final String subjectsTableName;
  private final String usedLinkDeviceTokensTableName;

  @JsonCreator
  public AccountsTableConfiguration(
      @JsonProperty("tableName") final String tableName,
      @JsonProperty("principalTableName") final String principalTableName,
      @JsonProperty("principalNameIdentifierTableName") final String principalNameIdentifierTableName,
      @JsonProperty("usernamesTableName") final String usernamesTableName,
      @JsonProperty("subjectsTableName") final String subjectsTableName,
      @JsonProperty("usedLinkDeviceTokensTableName") final String usedLinkDeviceTokensTableName) {

    super(tableName);

    this.principalTableName = principalTableName;
    this.principalNameIdentifierTableName = principalNameIdentifierTableName;
    this.usernamesTableName = usernamesTableName;
    this.subjectsTableName = subjectsTableName;
    this.usedLinkDeviceTokensTableName = usedLinkDeviceTokensTableName;
  }

  @NotBlank
  public String getPrincipalTableName() {
    return principalTableName;
  }

  @NotBlank
  public String getPrincipalNameIdentifierTableName() {
    return principalNameIdentifierTableName;
  }

  @NotBlank
  public String getUsernamesTableName() {
    return usernamesTableName;
  }

  @NotBlank
  public String getSubjectsTableName() {
    return subjectsTableName;
  }

  @NotBlank
  public String getUsedLinkDeviceTokensTableName() {
    return usedLinkDeviceTokensTableName;
  }
}
