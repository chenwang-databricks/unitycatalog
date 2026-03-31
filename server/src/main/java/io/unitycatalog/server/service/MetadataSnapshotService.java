package io.unitycatalog.server.service;

import com.linecorp.armeria.common.HttpResponse;
import com.linecorp.armeria.server.annotation.ExceptionHandler;
import com.linecorp.armeria.server.annotation.Post;
import io.unitycatalog.server.auth.UnityCatalogAuthorizer;
import io.unitycatalog.server.auth.annotation.AuthorizeExpression;
import io.unitycatalog.server.exception.BaseException;
import io.unitycatalog.server.exception.ErrorCode;
import io.unitycatalog.server.exception.GlobalExceptionHandler;
import io.unitycatalog.server.model.CatalogInfo;
import io.unitycatalog.server.model.MetadataAndPermissionsSnapshotRequest;
import io.unitycatalog.server.model.MetadataAndPermissionsSnapshotResponse;
import io.unitycatalog.server.model.MetadataSnapshotResponse;
import io.unitycatalog.server.model.MissingReason;
import io.unitycatalog.server.model.SchemaInfo;
import io.unitycatalog.server.model.Securable;
import io.unitycatalog.server.model.SecurableType;
import io.unitycatalog.server.model.TableInfo;
import io.unitycatalog.server.model.TableResult;
import io.unitycatalog.server.persist.CatalogRepository;
import io.unitycatalog.server.persist.MetastoreRepository;
import io.unitycatalog.server.persist.Repositories;
import io.unitycatalog.server.persist.SchemaRepository;
import io.unitycatalog.server.persist.TableRepository;
import io.unitycatalog.server.persist.model.Privileges;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import lombok.SneakyThrows;

@ExceptionHandler(GlobalExceptionHandler.class)
public class MetadataSnapshotService extends AuthorizedService {

  private final TableRepository tableRepository;
  private final CatalogRepository catalogRepository;
  private final SchemaRepository schemaRepository;
  private final MetastoreRepository metastoreRepository;

  @SneakyThrows
  public MetadataSnapshotService(UnityCatalogAuthorizer authorizer, Repositories repositories) {
    super(authorizer, repositories);
    this.tableRepository = repositories.getTableRepository();
    this.catalogRepository = repositories.getCatalogRepository();
    this.schemaRepository = repositories.getSchemaRepository();
    this.metastoreRepository = repositories.getMetastoreRepository();
  }

  @Post("")
  @AuthorizeExpression("#defer")
  public HttpResponse getMetadataAndPermissionsSnapshot(
      MetadataAndPermissionsSnapshotRequest request) {
    if (request == null || request.getSecurables() == null || request.getSecurables().isEmpty()) {
      throw new BaseException(ErrorCode.INVALID_ARGUMENT, "At least one securable is required");
    }

    boolean expandDeps =
        request.getIncludeViewDependencyExpansion() != null
            && request.getIncludeViewDependencyExpansion();

    MetadataSnapshotResponse innerResponse = new MetadataSnapshotResponse();
    List<TableResult> allTableResults = new ArrayList<>();

    for (Securable securable : request.getSecurables()) {
      if (securable.getType() == SecurableType.TABLE) {
        MetadataSnapshotResponse partialResponse =
            tableRepository.getMetadataSnapshot(securable.getFullName(), expandDeps);
        if (partialResponse.getTables() != null && !partialResponse.getTables().isEmpty()) {
          TableResult primaryResult = partialResponse.getTables().get(0);
          if (primaryResult.getTable() != null && isAuthorizedForTable(primaryResult.getTable())) {
            allTableResults.addAll(partialResponse.getTables());
          }
        }
      } else {
        allTableResults.add(
            new TableResult()
                .reason(
                    new MissingReason()
                        .name(securable.getFullName())
                        .reason(
                            "Unsupported securable type for metadata snapshot: "
                                + securable.getType())));
      }
    }

    innerResponse.setTables(allTableResults);

    MetadataAndPermissionsSnapshotResponse response =
        new MetadataAndPermissionsSnapshotResponse().metadata(innerResponse);
    return HttpResponse.ofJson(response);
  }

  private boolean isAuthorizedForTable(TableInfo tableInfo) {
    UUID principalId = userRepository.findPrincipalId();
    UUID metastoreId = metastoreRepository.getMetastoreId();

    if (authorizer.authorize(principalId, metastoreId, Privileges.OWNER)) {
      return true;
    }

    CatalogInfo catalogInfo = catalogRepository.getCatalog(tableInfo.getCatalogName());
    UUID catalogId = UUID.fromString(catalogInfo.getId());

    if (authorizer.authorize(principalId, catalogId, Privileges.OWNER)) {
      return true;
    }

    SchemaInfo schemaInfo =
        schemaRepository.getSchema(tableInfo.getCatalogName() + "." + tableInfo.getSchemaName());
    UUID schemaId = UUID.fromString(schemaInfo.getSchemaId());
    UUID tableId = UUID.fromString(tableInfo.getTableId());

    if (authorizer.authorize(principalId, schemaId, Privileges.OWNER)
        && authorizer.authorize(principalId, catalogId, Privileges.USE_CATALOG)) {
      return true;
    }

    return authorizer.authorize(principalId, schemaId, Privileges.USE_SCHEMA)
        && authorizer.authorize(principalId, catalogId, Privileges.USE_CATALOG)
        && (authorizer.authorize(principalId, tableId, Privileges.OWNER)
            || authorizer.authorize(principalId, tableId, Privileges.SELECT));
  }
}
