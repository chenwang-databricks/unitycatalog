package io.unitycatalog.server.service;

import com.linecorp.armeria.common.HttpResponse;
import com.linecorp.armeria.server.annotation.ExceptionHandler;
import com.linecorp.armeria.server.annotation.Post;
import io.unitycatalog.server.auth.UnityCatalogAuthorizer;
import io.unitycatalog.server.auth.annotation.AuthorizeExpression;
import io.unitycatalog.server.auth.annotation.AuthorizeResourceKey;
import io.unitycatalog.server.auth.annotation.AuthorizeKey;
import io.unitycatalog.server.exception.BaseException;
import io.unitycatalog.server.exception.ErrorCode;
import io.unitycatalog.server.exception.GlobalExceptionHandler;
import io.unitycatalog.server.model.Dependent;
import io.unitycatalog.server.model.GenerateTemporaryTableCredential;
import io.unitycatalog.server.model.TableOperation;
import io.unitycatalog.server.persist.DependencyRepository;
import io.unitycatalog.server.persist.Repositories;
import io.unitycatalog.server.persist.SchemaRepository;
import io.unitycatalog.server.persist.TableRepository;
import io.unitycatalog.server.persist.UserRepository;
import io.unitycatalog.server.persist.dao.DependencyDAO;
import io.unitycatalog.server.persist.dao.TableInfoDAO;
import io.unitycatalog.server.persist.model.Privileges;
import io.unitycatalog.server.persist.utils.TransactionManager;
import io.unitycatalog.server.service.credential.CredentialContext;
import io.unitycatalog.server.service.credential.StorageCredentialVendor;
import io.unitycatalog.server.utils.NormalizedURL;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.hibernate.SessionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static io.unitycatalog.server.model.SecurableType.TABLE;
import static io.unitycatalog.server.service.credential.CredentialContext.Privilege.SELECT;
import static io.unitycatalog.server.service.credential.CredentialContext.Privilege.UPDATE;

@ExceptionHandler(GlobalExceptionHandler.class)
public class TemporaryTableCredentialsService {
  private static final Logger LOGGER =
      LoggerFactory.getLogger(TemporaryTableCredentialsService.class);

  private final TableRepository tableRepository;
  private final DependencyRepository dependencyRepository;
  private final SchemaRepository schemaRepository;
  private final UserRepository userRepository;
  private final StorageCredentialVendor storageCredentialVendor;
  private final UnityCatalogAuthorizer authorizer;
  private final SessionFactory sessionFactory;

  public TemporaryTableCredentialsService(
      StorageCredentialVendor storageCredentialVendor,
      UnityCatalogAuthorizer authorizer,
      Repositories repositories) {
    this.storageCredentialVendor = storageCredentialVendor;
    this.authorizer = authorizer;
    this.tableRepository = repositories.getTableRepository();
    this.dependencyRepository = repositories.getDependencyRepository();
    this.schemaRepository = repositories.getSchemaRepository();
    this.userRepository = repositories.getUserRepository();
    this.sessionFactory = repositories.getSessionFactory();
  }

  @Post("")
  @AuthorizeExpression("""
      #dependent != null || (
        #authorizeAny(#principal, #schema, OWNER, USE_SCHEMA) &&
        #authorizeAny(#principal, #catalog, OWNER, USE_CATALOG) &&
        (#operation == 'READ'
          ? #authorizeAny(#principal, #table, OWNER, SELECT)
          : (#authorize(#principal, #table, OWNER) ||
             #authorizeAll(#principal, #table, SELECT, MODIFY)))
      )
      """)
  public HttpResponse generateTemporaryTableCredential(
      @AuthorizeResourceKey(value = TABLE, key = "table_id")
      @AuthorizeKey(key = "operation")
      @AuthorizeKey(key = "dependent")
      GenerateTemporaryTableCredential generateTemporaryTableCredential) {
    String tableId = generateTemporaryTableCredential.getTableId();
    Dependent dependent = generateTemporaryTableCredential.getDependent();

    if (dependent != null && dependent.getTable() != null
        && dependent.getTable().getTableId() != null) {
      return handleDependentCredentialRequest(
          tableId,
          dependent.getTable().getTableId(),
          generateTemporaryTableCredential.getOperation());
    }

    NormalizedURL storageLocation = tableRepository.getStorageLocationForTableOrStagingTable(
        UUID.fromString(tableId));
    return HttpResponse.ofJson(storageCredentialVendor.vendCredential(storageLocation,
        tableOperationToPrivileges(generateTemporaryTableCredential.getOperation())));
  }

  /**
   * Handles credential requests that come through a view/metric-view (definer's-rights model).
   *
   * Authorization checks:
   * 1. Current user has SELECT on the dependent (view/metric view)
   * 2. The requested table_id is in the dependent's dependency list
   * 3. The dependent's owner has SELECT on the source table
   */
  private HttpResponse handleDependentCredentialRequest(
      String sourceTableId, String dependentId, TableOperation operation) {
    return TransactionManager.executeWithTransaction(
        sessionFactory,
        session -> {
          UUID dependentUUID = UUID.fromString(dependentId);
          UUID sourceTableUUID = UUID.fromString(sourceTableId);

          TableInfoDAO dependentTable = tableRepository.getTableById(session, dependentUUID);
          if (dependentTable == null) {
            throw new BaseException(
                ErrorCode.NOT_FOUND, "Dependent table not found: " + dependentId);
          }

          UUID principalId = userRepository.findPrincipalId();
          if (principalId != null) {
            boolean userCanSelectView = authorizer.authorizeAny(
                principalId, dependentUUID, Privileges.OWNER, Privileges.SELECT);
            if (!userCanSelectView) {
              throw new BaseException(
                  ErrorCode.PERMISSION_DENIED,
                  "User does not have SELECT permission on the metric view");
            }
          }

          List<DependencyDAO> deps =
              dependencyRepository.getDependencies(session, dependentUUID, "TABLE");
          boolean sourceInDeps = deps.stream().anyMatch(dep -> {
            if (dep.getDependencyTargetId() != null) {
              return dep.getDependencyTargetId().equals(sourceTableUUID);
            }
            String fullName = dep.getDependencyFullName();
            if (fullName != null) {
              try {
                String[] parts = fullName.split("\\.");
                if (parts.length == 3) {
                  UUID schemaId = schemaRepository.getSchemaIdOrThrow(
                      session, parts[0], parts[1]);
                  TableInfoDAO resolved = tableRepository.findBySchemaIdAndName(
                      session, schemaId, parts[2]);
                  return resolved != null && resolved.getId().equals(sourceTableUUID);
                }
              } catch (Exception e) {
                LOGGER.warn("Failed to resolve dependency: {}", fullName, e);
              }
            }
            return false;
          });

          if (!sourceInDeps) {
            throw new BaseException(
                ErrorCode.PERMISSION_DENIED,
                "Source table is not a dependency of the specified metric view");
          }

          String viewOwner = dependentTable.getOwner();
          if (viewOwner != null && principalId != null) {
            try {
              UUID ownerPrincipalId = UUID.fromString(
                  userRepository.getUserByEmail(viewOwner).getId());
              boolean ownerCanSelectSource = authorizer.authorizeAny(
                  ownerPrincipalId, sourceTableUUID, Privileges.OWNER, Privileges.SELECT);
              if (!ownerCanSelectSource) {
                throw new BaseException(
                    ErrorCode.PERMISSION_DENIED,
                    "Metric view owner does not have SELECT permission on the source table");
              }
            } catch (BaseException e) {
              if (e.getErrorCode() == ErrorCode.PERMISSION_DENIED) {
                throw e;
              }
              LOGGER.warn("Could not resolve view owner for auth check: {}", viewOwner);
            }
          }

          NormalizedURL storageLocation = tableRepository
              .getStorageLocationForTableOrStagingTable(sourceTableUUID);
          return HttpResponse.ofJson(storageCredentialVendor.vendCredential(
              storageLocation, tableOperationToPrivileges(operation)));
        },
        "Failed to handle dependent credential request",
        /* readOnly = */ true);
  }

  private Set<CredentialContext.Privilege> tableOperationToPrivileges(
      TableOperation tableOperation) {
    return switch (tableOperation) {
      case READ -> Set.of(SELECT);
      case READ_WRITE -> Set.of(SELECT, UPDATE);
      case UNKNOWN_TABLE_OPERATION -> Collections.emptySet();
    };
  }
}
