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
import io.unitycatalog.client.model.Dependent;
import io.unitycatalog.client.model.GenerateTemporaryTableCredential;
import io.unitycatalog.client.model.MetadataAndPermissionsSnapshotRequest;
import io.unitycatalog.client.model.MetadataAndPermissionsSnapshotResponse;
import io.unitycatalog.client.model.MetadataSnapshotResponse;
import io.unitycatalog.client.model.Securable;
import io.unitycatalog.client.model.SecurableType;
import io.unitycatalog.client.model.TableDependency;
import io.unitycatalog.client.model.TableDependent;
import io.unitycatalog.client.model.TableInfo;
import io.unitycatalog.client.model.TableOperation;
import io.unitycatalog.client.model.TableResult;
import io.unitycatalog.client.model.TableType;
import io.unitycatalog.server.base.ServerConfig;
import io.unitycatalog.server.exception.ErrorCode;
import io.unitycatalog.server.persist.model.Privileges;
import io.unitycatalog.server.utils.TestUtils;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Tests the definer's-rights permission model for metric view credential vending.
 *
 * <p>When a user queries a metric view, the Spark connector requests temporary credentials for the
 * source table with the metric view ID as the {@code dependent} parameter. The server's {@code
 * handleDependentCredentialRequest} performs three authorization checks:
 *
 * <ol>
 *   <li>The requesting user has SELECT on the metric view (dependent)
 *   <li>The source table is in the metric view's dependency list
 *   <li>The metric view's owner has SELECT on the source table (definer's rights)
 * </ol>
 *
 * <p>This test validates all three checks: one positive case and three negative cases (one for each
 * check failing).
 */
public class SdkMetricViewAccessControlTest extends SdkAccessControlBaseCRUDTest {

  private static final String VIEW_OWNER_EMAIL = "view_owner@test.com";
  private static final String READER_EMAIL = "reader@test.com";

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

  private static Dependent makeDependentFromView(TableInfo metricView) {
    return new Dependent().table(new TableDependent().tableId(metricView.getTableId()));
  }

  /**
   * Positive test: view-mediated credential vending succeeds when all three checks pass.
   *
   * <p>The view owner has SELECT on the source table, the reader has SELECT on the metric view, and
   * the source table is in the metric view's dependency list.
   */
  @Test
  public void testDefinerRightsPositive() throws Exception {
    createTestUser(VIEW_OWNER_EMAIL, "View Owner");
    createTestUser(READER_EMAIL, "Reader");

    TablesApi adminTablesApi = new TablesApi(adminApiClient);
    TableInfo sourceTable = createSourceTable(adminTablesApi);

    grantViewOwnerBasePermissions();
    grantPermissions(
        VIEW_OWNER_EMAIL,
        SecurableType.SCHEMA,
        TestUtils.SCHEMA_FULL_NAME,
        Privileges.CREATE_TABLE);
    grantPermissions(
        VIEW_OWNER_EMAIL, SecurableType.TABLE, SOURCE_TABLE_FULL_NAME, Privileges.SELECT);

    ServerConfig viewOwnerConfig = createTestUserServerConfig(VIEW_OWNER_EMAIL);
    TablesApi viewOwnerTablesApi = new TablesApi(TestUtils.createApiClient(viewOwnerConfig));
    TableInfo metricView = createMetricView(viewOwnerTablesApi, sourceTable);

    grantReaderBasePermissions();
    grantPermissions(READER_EMAIL, SecurableType.TABLE, METRIC_VIEW_FULL_NAME, Privileges.SELECT);

    ServerConfig readerConfig = createTestUserServerConfig(READER_EMAIL);
    TemporaryCredentialsApi readerTempCredsApi =
        new TemporaryCredentialsApi(TestUtils.createApiClient(readerConfig));

    GenerateTemporaryTableCredential credRequest =
        new GenerateTemporaryTableCredential()
            .tableId(sourceTable.getTableId())
            .operation(TableOperation.READ)
            .dependent(makeDependentFromView(metricView));

    readerTempCredsApi.generateTemporaryTableCredentials(credRequest);
  }

  /**
   * Negative test: credential vending fails when the user lacks SELECT on the metric view.
   *
   * <p>This validates authorization check #1.
   */
  @Test
  public void testDeniedWhenUserLacksSelectOnView() throws Exception {
    createTestUser(VIEW_OWNER_EMAIL, "View Owner");
    createTestUser(READER_EMAIL, "Reader");

    TablesApi adminTablesApi = new TablesApi(adminApiClient);
    TableInfo sourceTable = createSourceTable(adminTablesApi);

    grantViewOwnerBasePermissions();
    grantPermissions(
        VIEW_OWNER_EMAIL, SecurableType.TABLE, SOURCE_TABLE_FULL_NAME, Privileges.SELECT);
    grantPermissions(
        VIEW_OWNER_EMAIL,
        SecurableType.SCHEMA,
        TestUtils.SCHEMA_FULL_NAME,
        Privileges.CREATE_TABLE);

    ServerConfig viewOwnerConfig = createTestUserServerConfig(VIEW_OWNER_EMAIL);
    TablesApi viewOwnerTablesApi = new TablesApi(TestUtils.createApiClient(viewOwnerConfig));
    TableInfo metricView = createMetricView(viewOwnerTablesApi, sourceTable);

    grantReaderBasePermissions();

    ServerConfig readerConfig = createTestUserServerConfig(READER_EMAIL);
    TemporaryCredentialsApi readerTempCredsApi =
        new TemporaryCredentialsApi(TestUtils.createApiClient(readerConfig));

    GenerateTemporaryTableCredential credRequest =
        new GenerateTemporaryTableCredential()
            .tableId(sourceTable.getTableId())
            .operation(TableOperation.READ)
            .dependent(makeDependentFromView(metricView));

    assertThatExceptionOfType(ApiException.class)
        .isThrownBy(() -> readerTempCredsApi.generateTemporaryTableCredentials(credRequest))
        .satisfies(
            ex ->
                assertThat(ex.getCode())
                    .isEqualTo(ErrorCode.PERMISSION_DENIED.getHttpStatus().code()));
  }

  /**
   * Negative test: credential vending fails when the source table is not in the metric view's
   * dependency list.
   *
   * <p>This validates authorization check #2.
   */
  @Test
  public void testDeniedWhenSourceNotInDependencies() throws Exception {
    createTestUser(VIEW_OWNER_EMAIL, "View Owner");
    createTestUser(READER_EMAIL, "Reader");

    grantViewOwnerBasePermissions();
    grantPermissions(
        VIEW_OWNER_EMAIL,
        SecurableType.SCHEMA,
        TestUtils.SCHEMA_FULL_NAME,
        Privileges.CREATE_TABLE);

    TablesApi adminTablesApi = new TablesApi(adminApiClient);
    TableInfo sourceTable = createSourceTable(adminTablesApi);

    ServerConfig viewOwnerConfig = createTestUserServerConfig(VIEW_OWNER_EMAIL);
    TablesApi viewOwnerTablesApi = new TablesApi(TestUtils.createApiClient(viewOwnerConfig));

    CreateTable createMetricView =
        new CreateTable()
            .name(METRIC_VIEW_NAME)
            .catalogName(TestUtils.CATALOG_NAME)
            .schemaName(TestUtils.SCHEMA_NAME)
            .tableType(TableType.METRIC_VIEW)
            .viewDefinition(VIEW_DEFINITION);
    TableInfo metricView = viewOwnerTablesApi.createTable(createMetricView);

    grantReaderBasePermissions();
    grantPermissions(READER_EMAIL, SecurableType.TABLE, METRIC_VIEW_FULL_NAME, Privileges.SELECT);

    ServerConfig readerConfig = createTestUserServerConfig(READER_EMAIL);
    TemporaryCredentialsApi readerTempCredsApi =
        new TemporaryCredentialsApi(TestUtils.createApiClient(readerConfig));

    GenerateTemporaryTableCredential credRequest =
        new GenerateTemporaryTableCredential()
            .tableId(sourceTable.getTableId())
            .operation(TableOperation.READ)
            .dependent(makeDependentFromView(metricView));

    assertThatExceptionOfType(ApiException.class)
        .isThrownBy(() -> readerTempCredsApi.generateTemporaryTableCredentials(credRequest))
        .satisfies(
            ex ->
                assertThat(ex.getCode())
                    .isEqualTo(ErrorCode.PERMISSION_DENIED.getHttpStatus().code()));
  }

  /**
   * Negative test: credential vending fails when the metric view owner lacks SELECT on the source
   * table.
   *
   * <p>This validates authorization check #3 (definer's rights).
   */
  @Test
  public void testDeniedWhenOwnerLacksSelectOnSource() throws Exception {
    createTestUser(VIEW_OWNER_EMAIL, "View Owner");
    createTestUser(READER_EMAIL, "Reader");

    grantViewOwnerBasePermissions();
    grantPermissions(
        VIEW_OWNER_EMAIL,
        SecurableType.SCHEMA,
        TestUtils.SCHEMA_FULL_NAME,
        Privileges.CREATE_TABLE);

    TablesApi adminTablesApi = new TablesApi(adminApiClient);
    TableInfo sourceTable = createSourceTable(adminTablesApi);

    ServerConfig viewOwnerConfig = createTestUserServerConfig(VIEW_OWNER_EMAIL);
    TablesApi viewOwnerTablesApi = new TablesApi(TestUtils.createApiClient(viewOwnerConfig));
    TableInfo metricView = createMetricView(viewOwnerTablesApi, sourceTable);

    grantReaderBasePermissions();
    grantPermissions(READER_EMAIL, SecurableType.TABLE, METRIC_VIEW_FULL_NAME, Privileges.SELECT);

    ServerConfig readerConfig = createTestUserServerConfig(READER_EMAIL);
    TemporaryCredentialsApi readerTempCredsApi =
        new TemporaryCredentialsApi(TestUtils.createApiClient(readerConfig));

    GenerateTemporaryTableCredential credRequest =
        new GenerateTemporaryTableCredential()
            .tableId(sourceTable.getTableId())
            .operation(TableOperation.READ)
            .dependent(makeDependentFromView(metricView));

    assertThatExceptionOfType(ApiException.class)
        .isThrownBy(() -> readerTempCredsApi.generateTemporaryTableCredentials(credRequest))
        .satisfies(
            ex ->
                assertThat(ex.getCode())
                    .isEqualTo(ErrorCode.PERMISSION_DENIED.getHttpStatus().code()));
  }

  /**
   * Positive test: MAPS snapshot succeeds when the reader has SELECT on the metric view. The
   * response should include the source table's full metadata even though the reader has no direct
   * SELECT on it (definer's rights for metadata access).
   */
  @Test
  public void testMetadataSnapshotPositive() throws Exception {
    createTestUser(VIEW_OWNER_EMAIL, "View Owner");
    createTestUser(READER_EMAIL, "Reader");

    TablesApi adminTablesApi = new TablesApi(adminApiClient);
    TableInfo sourceTable = createSourceTable(adminTablesApi);

    grantViewOwnerBasePermissions();
    grantPermissions(
        VIEW_OWNER_EMAIL,
        SecurableType.SCHEMA,
        TestUtils.SCHEMA_FULL_NAME,
        Privileges.CREATE_TABLE);
    grantPermissions(
        VIEW_OWNER_EMAIL, SecurableType.TABLE, SOURCE_TABLE_FULL_NAME, Privileges.SELECT);

    ServerConfig viewOwnerConfig = createTestUserServerConfig(VIEW_OWNER_EMAIL);
    TablesApi viewOwnerTablesApi = new TablesApi(TestUtils.createApiClient(viewOwnerConfig));
    TableInfo metricView = createMetricView(viewOwnerTablesApi, sourceTable);

    grantReaderBasePermissions();
    grantPermissions(READER_EMAIL, SecurableType.TABLE, METRIC_VIEW_FULL_NAME, Privileges.SELECT);

    ServerConfig readerConfig = createTestUserServerConfig(READER_EMAIL);
    TablesApi readerTablesApi = new TablesApi(TestUtils.createApiClient(readerConfig));

    MetadataAndPermissionsSnapshotRequest request =
        new MetadataAndPermissionsSnapshotRequest()
            .securables(
                List.of(new Securable().type(SecurableType.TABLE).fullName(METRIC_VIEW_FULL_NAME)))
            .includeViewDependencyExpansion(true);
    MetadataAndPermissionsSnapshotResponse response =
        readerTablesApi.getMetadataAndPermissionsSnapshot(request);

    MetadataSnapshotResponse metadata = response.getMetadata();
    assertThat(metadata).isNotNull();
    assertThat(metadata.getTables()).isNotNull();
    assertThat(metadata.getTables()).hasSizeGreaterThanOrEqualTo(2);

    TableResult viewResult = metadata.getTables().get(0);
    assertThat(viewResult.getTable()).isNotNull();
    assertThat(viewResult.getTable().getName()).isEqualTo(METRIC_VIEW_NAME);
    assertThat(viewResult.getTable().getTableType()).isEqualTo(TableType.METRIC_VIEW);

    TableResult sourceResult = metadata.getTables().get(1);
    assertThat(sourceResult.getTable()).isNotNull();
    assertThat(sourceResult.getTable().getName()).isEqualTo(SOURCE_TABLE_NAME);
    assertThat(sourceResult.getTable().getStorageLocation()).isNotNull();
    assertThat(sourceResult.getTable().getColumns()).isNotNull();
    assertThat(sourceResult.getTable().getColumns()).hasSizeGreaterThan(0);
  }

  /**
   * Negative test: MAPS snapshot filters out results when the reader lacks SELECT on the metric
   * view. The batch endpoint returns an empty tables list rather than a 403.
   */
  @Test
  public void testMetadataSnapshotDeniedNoSelectOnView() throws Exception {
    createTestUser(VIEW_OWNER_EMAIL, "View Owner");
    createTestUser(READER_EMAIL, "Reader");

    TablesApi adminTablesApi = new TablesApi(adminApiClient);
    TableInfo sourceTable = createSourceTable(adminTablesApi);

    grantViewOwnerBasePermissions();
    grantPermissions(
        VIEW_OWNER_EMAIL,
        SecurableType.SCHEMA,
        TestUtils.SCHEMA_FULL_NAME,
        Privileges.CREATE_TABLE);
    grantPermissions(
        VIEW_OWNER_EMAIL, SecurableType.TABLE, SOURCE_TABLE_FULL_NAME, Privileges.SELECT);

    ServerConfig viewOwnerConfig = createTestUserServerConfig(VIEW_OWNER_EMAIL);
    TablesApi viewOwnerTablesApi = new TablesApi(TestUtils.createApiClient(viewOwnerConfig));
    createMetricView(viewOwnerTablesApi, sourceTable);

    grantReaderBasePermissions();

    ServerConfig readerConfig = createTestUserServerConfig(READER_EMAIL);
    TablesApi readerTablesApi = new TablesApi(TestUtils.createApiClient(readerConfig));

    MetadataAndPermissionsSnapshotRequest request =
        new MetadataAndPermissionsSnapshotRequest()
            .securables(
                List.of(new Securable().type(SecurableType.TABLE).fullName(METRIC_VIEW_FULL_NAME)))
            .includeViewDependencyExpansion(true);
    MetadataAndPermissionsSnapshotResponse response =
        readerTablesApi.getMetadataAndPermissionsSnapshot(request);

    assertThat(response.getMetadata()).isNotNull();
    assertThat(response.getMetadata().getTables()).isEmpty();
  }

  /** Test: MAPS snapshot on a non-METRIC_VIEW returns the table without dependency expansion. */
  @Test
  public void testMetadataSnapshotNonMetricViewReturnsSingleTable() throws Exception {
    TablesApi adminTablesApi = new TablesApi(adminApiClient);
    createSourceTable(adminTablesApi);

    MetadataAndPermissionsSnapshotRequest request =
        new MetadataAndPermissionsSnapshotRequest()
            .securables(
                List.of(new Securable().type(SecurableType.TABLE).fullName(SOURCE_TABLE_FULL_NAME)))
            .includeViewDependencyExpansion(true);
    MetadataAndPermissionsSnapshotResponse response =
        adminTablesApi.getMetadataAndPermissionsSnapshot(request);

    assertThat(response.getMetadata()).isNotNull();
    assertThat(response.getMetadata().getTables()).hasSize(1);
    assertThat(response.getMetadata().getTables().get(0).getTable()).isNotNull();
    assertThat(response.getMetadata().getTables().get(0).getTable().getName())
        .isEqualTo(SOURCE_TABLE_NAME);
    assertThat(response.getMetadata().getTables().get(0).getTable().getTableType())
        .isEqualTo(TableType.EXTERNAL);
  }

  /**
   * Positive test: MAPS snapshot resolves full source table metadata including columns and storage
   * location, verifying the server-side resolution is complete.
   */
  @Test
  public void testMetadataSnapshotResolvesSourceMetadata() throws Exception {
    TablesApi adminTablesApi = new TablesApi(adminApiClient);
    TableInfo sourceTable = createSourceTable(adminTablesApi);
    TableInfo metricView = createMetricView(adminTablesApi, sourceTable);

    MetadataAndPermissionsSnapshotRequest request =
        new MetadataAndPermissionsSnapshotRequest()
            .securables(
                List.of(new Securable().type(SecurableType.TABLE).fullName(METRIC_VIEW_FULL_NAME)))
            .includeViewDependencyExpansion(true);
    MetadataAndPermissionsSnapshotResponse response =
        adminTablesApi.getMetadataAndPermissionsSnapshot(request);

    MetadataSnapshotResponse metadata = response.getMetadata();
    assertThat(metadata).isNotNull();
    assertThat(metadata.getTables()).hasSizeGreaterThanOrEqualTo(2);

    TableResult viewResult = metadata.getTables().get(0);
    assertThat(viewResult.getTable().getTableId()).isEqualTo(metricView.getTableId());
    assertThat(viewResult.getTable().getViewDefinition()).isEqualTo(VIEW_DEFINITION);
    assertThat(viewResult.getTable().getViewDependencies()).isNotNull();

    TableResult sourceResult = metadata.getTables().get(1);
    assertThat(sourceResult.getTable().getTableId()).isEqualTo(sourceTable.getTableId());
    assertThat(sourceResult.getTable().getCatalogName()).isEqualTo(TestUtils.CATALOG_NAME);
    assertThat(sourceResult.getTable().getSchemaName()).isEqualTo(TestUtils.SCHEMA_NAME);
    assertThat(sourceResult.getTable().getStorageLocation())
        .contains("uc-test-metric-view/" + SOURCE_TABLE_NAME);
    assertThat(sourceResult.getTable().getDataSourceFormat()).isEqualTo(DataSourceFormat.PARQUET);
    assertThat(sourceResult.getTable().getColumns()).hasSize(1);
    assertThat(sourceResult.getTable().getColumns().get(0).getName()).isEqualTo("amount");
  }

  /**
   * Positive test: batch request with multiple securables (metric view + regular table) returns
   * correct results for each.
   */
  @Test
  public void testMetadataSnapshotBatchMultipleSecurables() throws Exception {
    TablesApi adminTablesApi = new TablesApi(adminApiClient);
    TableInfo sourceTable = createSourceTable(adminTablesApi);
    TableInfo metricView = createMetricView(adminTablesApi, sourceTable);

    MetadataAndPermissionsSnapshotRequest request =
        new MetadataAndPermissionsSnapshotRequest()
            .securables(
                List.of(
                    new Securable().type(SecurableType.TABLE).fullName(METRIC_VIEW_FULL_NAME),
                    new Securable().type(SecurableType.TABLE).fullName(SOURCE_TABLE_FULL_NAME)))
            .includeViewDependencyExpansion(true);
    MetadataAndPermissionsSnapshotResponse response =
        adminTablesApi.getMetadataAndPermissionsSnapshot(request);

    MetadataSnapshotResponse metadata = response.getMetadata();
    assertThat(metadata).isNotNull();
    assertThat(metadata.getTables()).hasSizeGreaterThanOrEqualTo(3);

    assertThat(metadata.getTables().get(0).getTable().getName()).isEqualTo(METRIC_VIEW_NAME);
    assertThat(metadata.getTables().get(0).getTable().getTableType())
        .isEqualTo(TableType.METRIC_VIEW);

    boolean foundStandaloneSource = false;
    for (TableResult tr : metadata.getTables()) {
      if (tr.getTable() != null
          && SOURCE_TABLE_NAME.equals(tr.getTable().getName())
          && tr.getTable().getTableType() == TableType.EXTERNAL) {
        foundStandaloneSource = true;
      }
    }
    assertThat(foundStandaloneSource)
        .as("Response should include the standalone source table from the second securable")
        .isTrue();
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

  private void grantViewOwnerBasePermissions() throws Exception {
    grantPermissions(
        VIEW_OWNER_EMAIL, SecurableType.CATALOG, TestUtils.CATALOG_NAME, Privileges.USE_CATALOG);
    grantPermissions(
        VIEW_OWNER_EMAIL, SecurableType.SCHEMA, TestUtils.SCHEMA_FULL_NAME, Privileges.USE_SCHEMA);
  }

  private void grantReaderBasePermissions() throws Exception {
    grantPermissions(
        READER_EMAIL, SecurableType.CATALOG, TestUtils.CATALOG_NAME, Privileges.USE_CATALOG);
    grantPermissions(
        READER_EMAIL, SecurableType.SCHEMA, TestUtils.SCHEMA_FULL_NAME, Privileges.USE_SCHEMA);
  }
}
