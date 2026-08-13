using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace RemoteSSL.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AuditEvents",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Timestamp = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    Actor = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Action = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    ObjectType = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    ObjectId = table.Column<string>(type: "text", nullable: true),
                    TargetId = table.Column<Guid>(type: "uuid", nullable: true),
                    Result = table.Column<string>(type: "text", nullable: false),
                    CorrelationId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    DetailsJson = table.Column<string>(type: "jsonb", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditEvents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Certificates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    DisplayName = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    CommonName = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    Environment = table.Column<string>(type: "text", nullable: true),
                    OwnerId = table.Column<string>(type: "text", nullable: true),
                    RenewalPolicyId = table.Column<Guid>(type: "uuid", nullable: true),
                    HealthStatus = table.Column<int>(type: "integer", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Certificates", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CredentialRefs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    CredentialType = table.Column<int>(type: "integer", nullable: false),
                    Provider = table.Column<int>(type: "integer", nullable: false),
                    SecretIdentifier = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    Username = table.Column<string>(type: "text", nullable: true),
                    AccessPolicyJson = table.Column<string>(type: "jsonb", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CredentialRefs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Runners",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Segment = table.Column<string>(type: "text", nullable: true),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    CapabilitiesJson = table.Column<string>(type: "jsonb", nullable: false),
                    Version = table.Column<string>(type: "text", nullable: true),
                    IdentityCertThumbprint = table.Column<string>(type: "text", nullable: true),
                    LastHeartbeatAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    RegisteredAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Runners", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CertificateVersions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CertificateId = table.Column<Guid>(type: "uuid", nullable: false),
                    SerialNumber = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Sha256Thumbprint = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Sha1Thumbprint = table.Column<string>(type: "character varying(40)", maxLength: 40, nullable: false),
                    SubjectDn = table.Column<string>(type: "text", nullable: false),
                    IssuerDn = table.Column<string>(type: "text", nullable: false),
                    NotBefore = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    NotAfter = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    PublicKeyAlgorithm = table.Column<string>(type: "text", nullable: false),
                    KeySize = table.Column<int>(type: "integer", nullable: false),
                    SignatureAlgorithm = table.Column<string>(type: "text", nullable: false),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    PemCertificate = table.Column<string>(type: "text", nullable: true),
                    PemChain = table.Column<string>(type: "text", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateVersions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CertificateVersions_Certificates_CertificateId",
                        column: x => x.CertificateId,
                        principalTable: "Certificates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Targets",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    TargetType = table.Column<int>(type: "integer", nullable: false),
                    OsType = table.Column<string>(type: "text", nullable: true),
                    Environment = table.Column<string>(type: "text", nullable: true),
                    AdapterType = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ConnectionConfigJson = table.Column<string>(type: "jsonb", nullable: false),
                    CredentialRefId = table.Column<Guid>(type: "uuid", nullable: true),
                    RunnerId = table.Column<Guid>(type: "uuid", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Targets", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Targets_CredentialRefs_CredentialRefId",
                        column: x => x.CredentialRefId,
                        principalTable: "CredentialRefs",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "CertificateSans",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CertificateVersionId = table.Column<Guid>(type: "uuid", nullable: false),
                    SanType = table.Column<int>(type: "integer", nullable: false),
                    Value = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateSans", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CertificateSans_CertificateVersions_CertificateVersionId",
                        column: x => x.CertificateVersionId,
                        principalTable: "CertificateVersions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DeploymentJobs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CertificateVersionId = table.Column<Guid>(type: "uuid", nullable: false),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    Strategy = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    RequestedBy = table.Column<string>(type: "text", nullable: true),
                    ApprovedBy = table.Column<string>(type: "text", nullable: true),
                    CorrelationId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    StartedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    CompletedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeploymentJobs", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DeploymentJobs_CertificateVersions_CertificateVersionId",
                        column: x => x.CertificateVersionId,
                        principalTable: "CertificateVersions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MonitorEndpoints",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Host = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    Port = table.Column<int>(type: "integer", nullable: false),
                    Sni = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    ProbeIntervalMinutes = table.Column<int>(type: "integer", nullable: true),
                    LastProbeStatus = table.Column<int>(type: "integer", nullable: false),
                    LastProbeError = table.Column<string>(type: "text", nullable: true),
                    LastProbeAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LastObservedVersionId = table.Column<Guid>(type: "uuid", nullable: true),
                    LastHostnameValid = table.Column<bool>(type: "boolean", nullable: true),
                    LastChainValid = table.Column<bool>(type: "boolean", nullable: true),
                    LastChainError = table.Column<string>(type: "text", nullable: true),
                    LastTlsProtocol = table.Column<string>(type: "text", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MonitorEndpoints", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MonitorEndpoints_CertificateVersions_LastObservedVersionId",
                        column: x => x.LastObservedVersionId,
                        principalTable: "CertificateVersions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "CertificateStores",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    TargetId = table.Column<Guid>(type: "uuid", nullable: false),
                    StoreType = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    StorePath = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    Alias = table.Column<string>(type: "text", nullable: true),
                    ConfigJson = table.Column<string>(type: "jsonb", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificateStores", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CertificateStores_Targets_TargetId",
                        column: x => x.TargetId,
                        principalTable: "Targets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MonitorCertificateLinks",
                columns: table => new
                {
                    MonitorEndpointId = table.Column<Guid>(type: "uuid", nullable: false),
                    CertificateId = table.Column<Guid>(type: "uuid", nullable: false),
                    Source = table.Column<string>(type: "text", nullable: false),
                    FirstSeenAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastSeenAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MonitorCertificateLinks", x => new { x.MonitorEndpointId, x.CertificateId });
                    table.ForeignKey(
                        name: "FK_MonitorCertificateLinks_Certificates_CertificateId",
                        column: x => x.CertificateId,
                        principalTable: "Certificates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_MonitorCertificateLinks_MonitorEndpoints_MonitorEndpointId",
                        column: x => x.MonitorEndpointId,
                        principalTable: "MonitorEndpoints",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DeploymentBindings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CertificateId = table.Column<Guid>(type: "uuid", nullable: false),
                    CertificateStoreId = table.Column<Guid>(type: "uuid", nullable: false),
                    ServiceBindingJson = table.Column<string>(type: "jsonb", nullable: false),
                    ActivationPolicyJson = table.Column<string>(type: "jsonb", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeploymentBindings", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DeploymentBindings_CertificateStores_CertificateStoreId",
                        column: x => x.CertificateStoreId,
                        principalTable: "CertificateStores",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_DeploymentBindings_Certificates_CertificateId",
                        column: x => x.CertificateId,
                        principalTable: "Certificates",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DeploymentJobTargets",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    DeploymentJobId = table.Column<Guid>(type: "uuid", nullable: false),
                    DeploymentBindingId = table.Column<Guid>(type: "uuid", nullable: false),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    PreviousVersionId = table.Column<Guid>(type: "uuid", nullable: true),
                    StartedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    CompletedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeploymentJobTargets", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DeploymentJobTargets_DeploymentBindings_DeploymentBindingId",
                        column: x => x.DeploymentBindingId,
                        principalTable: "DeploymentBindings",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_DeploymentJobTargets_DeploymentJobs_DeploymentJobId",
                        column: x => x.DeploymentJobId,
                        principalTable: "DeploymentJobs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DeploymentSteps",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    DeploymentJobTargetId = table.Column<Guid>(type: "uuid", nullable: false),
                    StepType = table.Column<int>(type: "integer", nullable: false),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    RetryCount = table.Column<int>(type: "integer", nullable: false),
                    IdempotencyKey = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    SafeLog = table.Column<string>(type: "text", nullable: true),
                    StartedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    CompletedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeploymentSteps", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DeploymentSteps_DeploymentJobTargets_DeploymentJobTargetId",
                        column: x => x.DeploymentJobTargetId,
                        principalTable: "DeploymentJobTargets",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuditEvents_CorrelationId",
                table: "AuditEvents",
                column: "CorrelationId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditEvents_Timestamp",
                table: "AuditEvents",
                column: "Timestamp");

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_CommonName",
                table: "Certificates",
                column: "CommonName");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateSans_CertificateVersionId",
                table: "CertificateSans",
                column: "CertificateVersionId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateSans_Value",
                table: "CertificateSans",
                column: "Value");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateStores_TargetId",
                table: "CertificateStores",
                column: "TargetId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateVersions_CertificateId",
                table: "CertificateVersions",
                column: "CertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateVersions_IssuerDn_SerialNumber",
                table: "CertificateVersions",
                columns: new[] { "IssuerDn", "SerialNumber" });

            migrationBuilder.CreateIndex(
                name: "IX_CertificateVersions_NotAfter",
                table: "CertificateVersions",
                column: "NotAfter");

            migrationBuilder.CreateIndex(
                name: "IX_CertificateVersions_Sha256Thumbprint",
                table: "CertificateVersions",
                column: "Sha256Thumbprint",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentBindings_CertificateId",
                table: "DeploymentBindings",
                column: "CertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentBindings_CertificateStoreId",
                table: "DeploymentBindings",
                column: "CertificateStoreId");

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentJobs_CertificateVersionId",
                table: "DeploymentJobs",
                column: "CertificateVersionId");

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentJobs_CorrelationId",
                table: "DeploymentJobs",
                column: "CorrelationId");

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentJobTargets_DeploymentBindingId",
                table: "DeploymentJobTargets",
                column: "DeploymentBindingId");

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentJobTargets_DeploymentJobId",
                table: "DeploymentJobTargets",
                column: "DeploymentJobId");

            migrationBuilder.CreateIndex(
                name: "IX_DeploymentSteps_DeploymentJobTargetId",
                table: "DeploymentSteps",
                column: "DeploymentJobTargetId");

            migrationBuilder.CreateIndex(
                name: "IX_MonitorCertificateLinks_CertificateId",
                table: "MonitorCertificateLinks",
                column: "CertificateId");

            migrationBuilder.CreateIndex(
                name: "IX_MonitorEndpoints_Host_Port_Sni",
                table: "MonitorEndpoints",
                columns: new[] { "Host", "Port", "Sni" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MonitorEndpoints_LastObservedVersionId",
                table: "MonitorEndpoints",
                column: "LastObservedVersionId");

            migrationBuilder.CreateIndex(
                name: "IX_Targets_CredentialRefId",
                table: "Targets",
                column: "CredentialRefId");

            migrationBuilder.CreateIndex(
                name: "IX_Targets_Name",
                table: "Targets",
                column: "Name",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuditEvents");

            migrationBuilder.DropTable(
                name: "CertificateSans");

            migrationBuilder.DropTable(
                name: "DeploymentSteps");

            migrationBuilder.DropTable(
                name: "MonitorCertificateLinks");

            migrationBuilder.DropTable(
                name: "Runners");

            migrationBuilder.DropTable(
                name: "DeploymentJobTargets");

            migrationBuilder.DropTable(
                name: "MonitorEndpoints");

            migrationBuilder.DropTable(
                name: "DeploymentBindings");

            migrationBuilder.DropTable(
                name: "DeploymentJobs");

            migrationBuilder.DropTable(
                name: "CertificateStores");

            migrationBuilder.DropTable(
                name: "CertificateVersions");

            migrationBuilder.DropTable(
                name: "Targets");

            migrationBuilder.DropTable(
                name: "Certificates");

            migrationBuilder.DropTable(
                name: "CredentialRefs");
        }
    }
}
