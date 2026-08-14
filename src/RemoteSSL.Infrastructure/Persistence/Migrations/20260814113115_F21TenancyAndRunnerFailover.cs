using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RemoteSSL.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class F21TenancyAndRunnerFailover : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "Users",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "Targets",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "ServicePaths",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<string>(
                name: "AffinityGroup",
                table: "Runners",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "Runners",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<string>(
                name: "AffinityGroup",
                table: "RunnerJobs",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "Attempts",
                table: "RunnerJobs",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LeaseExpiresAt",
                table: "RunnerJobs",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "NonReassignable",
                table: "RunnerJobs",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<Guid>(
                name: "ReassignedFromRunnerId",
                table: "RunnerJobs",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "RunnerJobs",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "RenewalPolicies",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "MonitorEndpoints",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "MonitorCertificateLinks",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "ManagedKeys",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "DomainValidations",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "DeploymentSteps",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "DeploymentJobTargets",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "DeploymentJobs",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "DeploymentBindings",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "CredentialRefs",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "CertificateVersions",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "CertificateStores",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "CertificateSans",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "Certificates",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "CertificateRequests",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "CertificatePolicies",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "CaConnectors",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "Artifacts",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "ApprovalRequests",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.CreateTable(
                name: "Tenants",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Slug = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Tenants", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Tenants_Slug",
                table: "Tenants",
                column: "Slug",
                unique: true);

            // §35 upgrade path: everything that exists today belongs to the default tenant. Seeding
            // it and backfilling in the same migration means an existing single-tenant install
            // keeps working with no manual step — and nothing is left with an empty owner.
            migrationBuilder.Sql("""
                INSERT INTO "Tenants" ("Id", "Name", "Slug", "Enabled", "CreatedAt")
                VALUES ('00000000-0000-0000-0000-00000000d001', 'Default', 'default', true, now())
                ON CONFLICT ("Id") DO NOTHING;
                """);

            migrationBuilder.Sql("""
                UPDATE "ApprovalRequests" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "Artifacts" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "CaConnectors" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "CertificatePolicies" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "CertificateRequests" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "CertificateSans" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "CertificateStores" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "CertificateVersions" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "Certificates" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "CredentialRefs" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "DeploymentBindings" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "DeploymentJobTargets" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "DeploymentJobs" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "DeploymentSteps" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "DomainValidations" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "ManagedKeys" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "MonitorCertificateLinks" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "MonitorEndpoints" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "RenewalPolicies" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "RunnerJobs" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "Runners" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "ServicePaths" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "Targets" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);

            migrationBuilder.Sql("""
                UPDATE "Users" SET "TenantId" = '00000000-0000-0000-0000-00000000d001'
                WHERE "TenantId" = '00000000-0000-0000-0000-000000000000';
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Tenants");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "Targets");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "ServicePaths");

            migrationBuilder.DropColumn(
                name: "AffinityGroup",
                table: "Runners");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "Runners");

            migrationBuilder.DropColumn(
                name: "AffinityGroup",
                table: "RunnerJobs");

            migrationBuilder.DropColumn(
                name: "Attempts",
                table: "RunnerJobs");

            migrationBuilder.DropColumn(
                name: "LeaseExpiresAt",
                table: "RunnerJobs");

            migrationBuilder.DropColumn(
                name: "NonReassignable",
                table: "RunnerJobs");

            migrationBuilder.DropColumn(
                name: "ReassignedFromRunnerId",
                table: "RunnerJobs");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "RunnerJobs");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "RenewalPolicies");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "MonitorCertificateLinks");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "ManagedKeys");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "DomainValidations");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "DeploymentSteps");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "DeploymentJobTargets");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "DeploymentJobs");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "DeploymentBindings");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "CredentialRefs");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "CertificateVersions");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "CertificateStores");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "CertificateSans");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "CertificateRequests");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "CertificatePolicies");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "CaConnectors");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "Artifacts");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "ApprovalRequests");
        }
    }
}
