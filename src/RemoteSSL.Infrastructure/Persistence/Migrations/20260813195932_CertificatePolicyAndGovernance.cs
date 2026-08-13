using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RemoteSSL.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class CertificatePolicyAndGovernance : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "CertificatePolicyId",
                table: "Certificates",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Environment",
                table: "CertificateRequests",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "OwnerId",
                table: "CertificateRequests",
                type: "text",
                nullable: true);

            migrationBuilder.AlterColumn<Guid>(
                name: "DeploymentJobId",
                table: "ApprovalRequests",
                type: "uuid",
                nullable: true,
                oldClrType: typeof(Guid),
                oldType: "uuid");

            migrationBuilder.AddColumn<bool>(
                name: "BreakGlass",
                table: "ApprovalRequests",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<Guid>(
                name: "CertificateRequestId",
                table: "ApprovalRequests",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ObjectType",
                table: "ApprovalRequests",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateTable(
                name: "CertificatePolicies",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    IsDefault = table.Column<bool>(type: "boolean", nullable: false),
                    MinimumRsaBits = table.Column<int>(type: "integer", nullable: false),
                    AllowedEcCurvesJson = table.Column<string>(type: "text", nullable: false),
                    RenewBeforeDays = table.Column<int>(type: "integer", nullable: false),
                    RotateKeyOnRenewal = table.Column<bool>(type: "boolean", nullable: false),
                    RequireApprovalInJson = table.Column<string>(type: "text", nullable: false),
                    BlockWeakSignatureAlgorithms = table.Column<bool>(type: "boolean", nullable: false),
                    RequirePostDeploymentProbe = table.Column<bool>(type: "boolean", nullable: false),
                    AllowWildcard = table.Column<bool>(type: "boolean", nullable: false),
                    MaxValidityDays = table.Column<int>(type: "integer", nullable: true),
                    AllowedDomainSuffixesJson = table.Column<string>(type: "text", nullable: false),
                    BlockedDomainSuffixesJson = table.Column<string>(type: "text", nullable: false),
                    WarnOnOverlap = table.Column<bool>(type: "boolean", nullable: false),
                    RequireOwner = table.Column<bool>(type: "boolean", nullable: false),
                    RequireWindowInJson = table.Column<string>(type: "text", nullable: false),
                    EnforceSeparationOfDuties = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CertificatePolicies", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CertificatePolicies_IsDefault",
                table: "CertificatePolicies",
                column: "IsDefault");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CertificatePolicies");

            migrationBuilder.DropColumn(
                name: "CertificatePolicyId",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "Environment",
                table: "CertificateRequests");

            migrationBuilder.DropColumn(
                name: "OwnerId",
                table: "CertificateRequests");

            migrationBuilder.DropColumn(
                name: "BreakGlass",
                table: "ApprovalRequests");

            migrationBuilder.DropColumn(
                name: "CertificateRequestId",
                table: "ApprovalRequests");

            migrationBuilder.DropColumn(
                name: "ObjectType",
                table: "ApprovalRequests");

            migrationBuilder.AlterColumn<Guid>(
                name: "DeploymentJobId",
                table: "ApprovalRequests",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"),
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldNullable: true);
        }
    }
}
