package io.unitycatalog.server.base.table;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.unitycatalog.client.model.CreateTable;
import io.unitycatalog.client.model.Dependency;
import io.unitycatalog.client.model.DependencyList;
import io.unitycatalog.client.model.TableDependency;
import io.unitycatalog.client.model.TableInfo;
import io.unitycatalog.client.model.TableType;
import io.unitycatalog.server.utils.TestUtils;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

public abstract class BaseMetricViewCRUDTest extends BaseTableCRUDTestEnv {

  protected static final String METRIC_VIEW_NAME = "uc_test_metric_view";
  protected static final String METRIC_VIEW_FULL_NAME =
      TestUtils.CATALOG_NAME + "." + TestUtils.SCHEMA_NAME + "." + METRIC_VIEW_NAME;
  protected static final String VIEW_DEFINITION =
      "SELECT date_trunc('day', event_time) AS day, count(*) AS event_count FROM events GROUP BY 1";
  protected static final Map<String, String> PROPERTIES =
      Map.of("team", "analytics", "refresh", "daily");

  @Test
  public void testMetricViewCRUD() throws Exception {
    assertThatThrownBy(() -> tableOperations.getTable(METRIC_VIEW_FULL_NAME))
        .isInstanceOf(Exception.class);

    // --- Create ---
    CreateTable createRequest =
        new CreateTable()
            .name(METRIC_VIEW_NAME)
            .catalogName(TestUtils.CATALOG_NAME)
            .schemaName(TestUtils.SCHEMA_NAME)
            .tableType(TableType.METRIC_VIEW)
            .viewDefinition(VIEW_DEFINITION)
            .comment("Daily event counts by day")
            .properties(PROPERTIES);

    TableInfo created = tableOperations.createTable(createRequest);
    assertThat(created.getName()).isEqualTo(METRIC_VIEW_NAME);
    assertThat(created.getCatalogName()).isEqualTo(TestUtils.CATALOG_NAME);
    assertThat(created.getSchemaName()).isEqualTo(TestUtils.SCHEMA_NAME);
    assertThat(created.getTableType()).isEqualTo(TableType.METRIC_VIEW);
    assertThat(created.getViewDefinition()).isEqualTo(VIEW_DEFINITION);
    assertThat(created.getTableId()).isNotNull();
    assertThat(created.getStorageLocation())
        .as("Metric views should have no storage location")
        .isNull();

    // --- Get ---
    TableInfo fetched = tableOperations.getTable(METRIC_VIEW_FULL_NAME);
    assertThat(fetched.getName()).isEqualTo(METRIC_VIEW_NAME);
    assertThat(fetched.getTableType()).isEqualTo(TableType.METRIC_VIEW);
    assertThat(fetched.getViewDefinition()).isEqualTo(VIEW_DEFINITION);
    assertThat(fetched.getComment()).isEqualTo("Daily event counts by day");
    assertThat(fetched.getCreatedAt()).isNotNull();
    assertThat(fetched.getTableId()).isNotNull();

    // Verify properties round-trip
    assertThat(fetched.getProperties()).isNotNull();
    assertThat(fetched.getProperties().get("team")).isEqualTo("analytics");
    assertThat(fetched.getProperties().get("refresh")).isEqualTo("daily");

    // --- List ---
    List<TableInfo> tables =
        tableOperations.listTables(TestUtils.CATALOG_NAME, TestUtils.SCHEMA_NAME, Optional.empty());
    assertThat(tables)
        .as("Metric view should appear in listTables")
        .anyMatch(
            t ->
                METRIC_VIEW_NAME.equals(t.getName())
                    && TableType.METRIC_VIEW.equals(t.getTableType()));

    // --- Create without view_definition should fail ---
    CreateTable badRequest =
        new CreateTable()
            .name("bad_metric_view")
            .catalogName(TestUtils.CATALOG_NAME)
            .schemaName(TestUtils.SCHEMA_NAME)
            .tableType(TableType.METRIC_VIEW);
    assertThatThrownBy(() -> tableOperations.createTable(badRequest)).isInstanceOf(Exception.class);

    // --- Delete ---
    tableOperations.deleteTable(METRIC_VIEW_FULL_NAME);
    assertThatThrownBy(() -> tableOperations.getTable(METRIC_VIEW_FULL_NAME))
        .isInstanceOf(Exception.class);
  }

  @Test
  public void testMetricViewWithDependenciesAccepted() throws Exception {
    String sourceTableFullName =
        TestUtils.CATALOG_NAME + "." + TestUtils.SCHEMA_NAME + ".source_events";

    Dependency dep = new Dependency();
    dep.setTable(new TableDependency().tableFullName(sourceTableFullName));
    DependencyList depList = new DependencyList();
    depList.setDependencies(List.of(dep));

    CreateTable createRequest =
        new CreateTable()
            .name(METRIC_VIEW_NAME)
            .catalogName(TestUtils.CATALOG_NAME)
            .schemaName(TestUtils.SCHEMA_NAME)
            .tableType(TableType.METRIC_VIEW)
            .viewDefinition(VIEW_DEFINITION)
            .viewDependencies(depList)
            .comment("Metric view with dependencies in payload");

    TableInfo created = tableOperations.createTable(createRequest);
    assertThat(created.getTableType()).isEqualTo(TableType.METRIC_VIEW);
    assertThat(created.getViewDefinition()).isEqualTo(VIEW_DEFINITION);

    TableInfo fetched = tableOperations.getTable(METRIC_VIEW_FULL_NAME);
    assertThat(fetched.getTableType()).isEqualTo(TableType.METRIC_VIEW);
    assertThat(fetched.getViewDefinition()).isEqualTo(VIEW_DEFINITION);

    tableOperations.deleteTable(METRIC_VIEW_FULL_NAME);
    assertThatThrownBy(() -> tableOperations.getTable(METRIC_VIEW_FULL_NAME))
        .isInstanceOf(Exception.class);
  }
}
