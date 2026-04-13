package io.unitycatalog.server.sdk.access;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.unitycatalog.client.ApiException;
import io.unitycatalog.client.api.TablesApi;
import io.unitycatalog.client.api.TemporaryCredentialsApi;
import io.unitycatalog.client.model.ColumnInfo;
import io.unitycatalog.client.model.ColumnTypeName;
import io.unitycatalog.client.model.CreateTable;
import io.unitycatalog.client.model.DataSourceFormat;
import io.unitycatalog.client.model.Dependency;
import io.unitycatalog.client.model.DependencyList;
import io.unitycatalog.client.model.GenerateTemporaryTableCredential;
import io.unitycatalog.client.model.SecurableType;
import io.unitycatalog.client.model.TableDependency;
import io.unitycatalog.client.model.TableInfo;
import io.unitycatalog.client.model.TableOperation;
import io.unitycatalog.client.model.TableType;
import io.unitycatalog.server.base.ServerConfig;
import io.unitycatalog.server.exception.ErrorCode;
import io.unitycatalog.server.persist.model.Privileges;
import io.unitycatalog.server.utils.TestUtils;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Tests the invoker's-rights permission model for metric view access.
 *
 * <p>Under invoker's rights, the user querying a metric view must have SELECT on both the metric
 * view AND all source tables. There is no definer's rights bypass -- the user's own permissions are
 * checked directly on each table.
 *
 * <p>This matches the behavior of Databricks UC on non-PE (Single User) clusters, where untrusted
 * engines cannot be relied upon to enforce definer's rights.
 */
public class SdkMetricViewAccessControlTest extends SdkAccessControlBaseCRUDTest {

  private static final String USER_EMAIL = "metric_view_user@test.com";

  private static final String SOURCE_TABLE_NAME = "source_data";
  private static final String SOURCE_TABLE_FULL_NAME =
      TestUtils.CATALOG_NAME + "." + TestUtils.SCHEMA_NAME + "." + SOURCE_TABLE_NAME;

  private static final String METRIC_VIEW_NAME = "test_metric_view";
  private static final String METRIC_VIEW_FULL_NAME =
      TestUtils.CATALOG_NAME + "." + TestUtils.SCHEMA_NAME + "." + METRIC_VIEW_NAME;

  private static final String VIEW_DEFINITION =
      "version: \"0.1\"\nsource: "
          + SOURCE_TABLE_FULL_NAME
          + "\nmeasures:\n  - name: total\n    expr: SUM(amount)";

  private static final List<ColumnInfo> SOURCE_COLUMNS =
      List.of(
          new ColumnInfo()
              .name("amount")
              .typeText("DOUBLE")
              .typeJson("{\"type\": \"double\"}")
              .typeName(ColumnTypeName.DOUBLE)
              .position(0)
              .nullable(true));

  /**
   * Positive test: user with SELECT on both the metric view and source table can get credentials
   * for the source table (invoker's rights).
   */
  @Test
  public void testInvokerRightsPositive() throws Exception {
    createTestUser(USER_EMAIL, "Test User");

    TablesApi adminTablesApi = new TablesApi(adminApiClient);
    TableInfo sourceTable = createSourceTable(adminTablesApi);
    createMetricView(adminTablesApi, sourceTable);

    grantUserBasePermissions();
    grantPermissions(USER_EMAIL, SecurableType.TABLE, METRIC_VIEW_FULL_NAME, Privileges.SELECT);
    grantPermissions(USER_EMAIL, SecurableType.TABLE, SOURCE_TABLE_FULL_NAME, Privileges.SELECT);

    ServerConfig userConfig = createTestUserServerConfig(USER_EMAIL);
    TemporaryCredentialsApi userTempCredsApi =
        new TemporaryCredentialsApi(TestUtils.createApiClient(userConfig));

    GenerateTemporaryTableCredential credRequest =
        new GenerateTemporaryTableCredential()
            .tableId(sourceTable.getTableId())
            .operation(TableOperation.READ);

    userTempCredsApi.generateTemporaryTableCredentials(credRequest);
  }

  /**
   * Negative test: user with SELECT on the metric view but NOT on the source table is denied
   * credentials for the source table (invoker's rights -- no definer bypass).
   */
  @Test
  public void testInvokerRightsDeniedWithoutSourceSelect() throws Exception {
    createTestUser(USER_EMAIL, "Test User");

    TablesApi adminTablesApi = new TablesApi(adminApiClient);
    TableInfo sourceTable = createSourceTable(adminTablesApi);
    createMetricView(adminTablesApi, sourceTable);

    grantUserBasePermissions();
    grantPermissions(USER_EMAIL, SecurableType.TABLE, METRIC_VIEW_FULL_NAME, Privileges.SELECT);

    ServerConfig userConfig = createTestUserServerConfig(USER_EMAIL);
    TemporaryCredentialsApi userTempCredsApi =
        new TemporaryCredentialsApi(TestUtils.createApiClient(userConfig));

    GenerateTemporaryTableCredential credRequest =
        new GenerateTemporaryTableCredential()
            .tableId(sourceTable.getTableId())
            .operation(TableOperation.READ);

    assertThatExceptionOfType(ApiException.class)
        .isThrownBy(() -> userTempCredsApi.generateTemporaryTableCredentials(credRequest))
        .satisfies(
            ex ->
                assertThat(ex.getCode())
                    .isEqualTo(ErrorCode.PERMISSION_DENIED.getHttpStatus().code()));
  }

  /**
   * Test: user can read metric view metadata (GET /tables) with SELECT on the metric view, even
   * without SELECT on the source table. Metadata access is allowed.
   */
  @Test
  public void testMetricViewMetadataAccessible() throws Exception {
    createTestUser(USER_EMAIL, "Test User");

    TablesApi adminTablesApi = new TablesApi(adminApiClient);
    TableInfo sourceTable = createSourceTable(adminTablesApi);
    createMetricView(adminTablesApi, sourceTable);

    grantUserBasePermissions();
    grantPermissions(USER_EMAIL, SecurableType.TABLE, METRIC_VIEW_FULL_NAME, Privileges.SELECT);

    ServerConfig userConfig = createTestUserServerConfig(USER_EMAIL);
    TablesApi userTablesApi = new TablesApi(TestUtils.createApiClient(userConfig));

    TableInfo metricViewInfo = userTablesApi.getTable(METRIC_VIEW_FULL_NAME, false, false);
    assertThat(metricViewInfo).isNotNull();
    assertThat(metricViewInfo.getTableType()).isEqualTo(TableType.METRIC_VIEW);
    assertThat(metricViewInfo.getViewDefinition()).isEqualTo(VIEW_DEFINITION);
    assertThat(metricViewInfo.getViewDependencies()).isNotNull();
  }

  /** Negative test: user without SELECT on the metric view cannot access its metadata. */
  @Test
  public void testMetricViewMetadataDeniedWithoutSelect() throws Exception {
    createTestUser(USER_EMAIL, "Test User");

    TablesApi adminTablesApi = new TablesApi(adminApiClient);
    TableInfo sourceTable = createSourceTable(adminTablesApi);
    createMetricView(adminTablesApi, sourceTable);

    grantUserBasePermissions();

    ServerConfig userConfig = createTestUserServerConfig(USER_EMAIL);
    TablesApi userTablesApi = new TablesApi(TestUtils.createApiClient(userConfig));

    assertThatExceptionOfType(ApiException.class)
        .isThrownBy(() -> userTablesApi.getTable(METRIC_VIEW_FULL_NAME, false, false))
        .satisfies(
            ex ->
                assertThat(ex.getCode())
                    .isEqualTo(ErrorCode.PERMISSION_DENIED.getHttpStatus().code()));
  }

  private TableInfo createSourceTable(TablesApi tablesApi) throws ApiException {
    CreateTable createTable =
        new CreateTable()
            .name(SOURCE_TABLE_NAME)
            .catalogName(TestUtils.CATALOG_NAME)
            .schemaName(TestUtils.SCHEMA_NAME)
            .columns(SOURCE_COLUMNS)
            .tableType(TableType.EXTERNAL)
            .dataSourceFormat(DataSourceFormat.PARQUET)
            .storageLocation("file:///tmp/uc-test-metric-view/" + SOURCE_TABLE_NAME);
    return tablesApi.createTable(createTable);
  }

  private TableInfo createMetricView(TablesApi tablesApi, TableInfo sourceTable)
      throws ApiException {
    Dependency dep = new Dependency();
    dep.setTable(new TableDependency().tableFullName(SOURCE_TABLE_FULL_NAME));
    DependencyList depList = new DependencyList();
    depList.setDependencies(List.of(dep));

    CreateTable createMetricView =
        new CreateTable()
            .name(METRIC_VIEW_NAME)
            .catalogName(TestUtils.CATALOG_NAME)
            .schemaName(TestUtils.SCHEMA_NAME)
            .tableType(TableType.METRIC_VIEW)
            .viewDefinition(VIEW_DEFINITION)
            .viewDependencies(depList);
    return tablesApi.createTable(createMetricView);
  }

  private void grantUserBasePermissions() throws Exception {
    grantPermissions(
        USER_EMAIL, SecurableType.CATALOG, TestUtils.CATALOG_NAME, Privileges.USE_CATALOG);
    grantPermissions(
        USER_EMAIL, SecurableType.SCHEMA, TestUtils.SCHEMA_FULL_NAME, Privileges.USE_SCHEMA);
  }
}
