package io.unitycatalog.server.persist.dao;

import io.unitycatalog.server.model.Dependency;
import io.unitycatalog.server.model.TableDependency;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.UuidGenerator;

@Entity
@Table(
    name = "uc_dependencies",
    indexes = {
      @Index(name = "idx_dependent", columnList = "dependent_type,dependent_id"),
    })
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
@ToString
@Builder
public class DependencyDAO {
  @Id
  @UuidGenerator
  @Column(name = "id", updatable = false, nullable = false)
  private UUID id;

  @Column(name = "dependent_type", nullable = false)
  private String dependentType;

  @Column(name = "dependent_id", nullable = false)
  private UUID dependentId;

  @Column(name = "dependency_type", nullable = false)
  private String dependencyType;

  @Column(name = "dependency_catalog")
  private String dependencyCatalog;

  @Column(name = "dependency_schema")
  private String dependencySchema;

  @Column(name = "dependency_name")
  private String dependencyName;

  @Column(name = "dependency_target_id")
  private UUID dependencyTargetId;

  /** Converts a Dependency API model to a DependencyDAO for a given dependent. */
  public static DependencyDAO from(Dependency dependency, UUID dependentId, String dependentType) {
    DependencyDAOBuilder builder =
        DependencyDAO.builder().dependentId(dependentId).dependentType(dependentType);

    if (dependency.getTable() != null) {
      builder.dependencyType("TABLE");
      String fullName = dependency.getTable().getTableFullName();
      String[] parts = fullName.split("\\.");
      if (parts.length == 3) {
        builder.dependencyCatalog(parts[0]);
        builder.dependencySchema(parts[1]);
        builder.dependencyName(parts[2]);
      } else {
        builder.dependencyName(fullName);
      }
    }

    return builder.build();
  }

  /** Converts this DAO to a Dependency API model. */
  public Dependency toDependency() {
    Dependency dependency = new Dependency();
    if ("TABLE".equals(dependencyType)) {
      String fullName = dependencyCatalog + "." + dependencySchema + "." + dependencyName;
      dependency.setTable(new TableDependency().tableFullName(fullName));
    }
    return dependency;
  }

  public String getDependencyFullName() {
    if (dependencyCatalog != null && dependencySchema != null && dependencyName != null) {
      return dependencyCatalog + "." + dependencySchema + "." + dependencyName;
    }
    return dependencyName;
  }

  public static List<Dependency> toDependencyList(List<DependencyDAO> daos) {
    if (daos == null) {
      return new ArrayList<>();
    }
    return daos.stream().map(DependencyDAO::toDependency).collect(Collectors.toList());
  }
}
