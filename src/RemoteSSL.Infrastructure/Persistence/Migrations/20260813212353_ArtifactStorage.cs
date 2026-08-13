using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RemoteSSL.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class ArtifactStorage : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Artifacts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Kind = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Sensitivity = table.Column<int>(type: "integer", nullable: false),
                    CertificateId = table.Column<Guid>(type: "uuid", nullable: true),
                    CertificateVersionId = table.Column<Guid>(type: "uuid", nullable: true),
                    DeploymentJobId = table.Column<Guid>(type: "uuid", nullable: true),
                    TargetId = table.Column<Guid>(type: "uuid", nullable: true),
                    FileName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    ContentType = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    SizeBytes = table.Column<long>(type: "bigint", nullable: false),
                    Sha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    StorageProvider = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    StorageRef = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Ciphertext = table.Column<byte[]>(type: "bytea", nullable: true),
                    Nonce = table.Column<byte[]>(type: "bytea", nullable: false),
                    Tag = table.Column<byte[]>(type: "bytea", nullable: false),
                    WrappedDataKey = table.Column<string>(type: "text", nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    CreatedBy = table.Column<string>(type: "text", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    PurgedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    PurgeReason = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Artifacts", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Artifacts_CertificateVersionId",
                table: "Artifacts",
                column: "CertificateVersionId");

            migrationBuilder.CreateIndex(
                name: "IX_Artifacts_DeploymentJobId",
                table: "Artifacts",
                column: "DeploymentJobId");

            migrationBuilder.CreateIndex(
                name: "IX_Artifacts_ExpiresAt_PurgedAt",
                table: "Artifacts",
                columns: new[] { "ExpiresAt", "PurgedAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Artifacts");
        }
    }
}
