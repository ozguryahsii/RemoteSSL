using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RemoteSSL.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class F16SecretProvidersAndManagedKeys : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LastAccessedAt",
                table: "CredentialRefs",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LastAccessedBy",
                table: "CredentialRefs",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LastRotatedAt",
                table: "CredentialRefs",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "RotationIntervalDays",
                table: "CredentialRefs",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<bool>(
                name: "RotationPending",
                table: "CredentialRefs",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.CreateTable(
                name: "ManagedKeys",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Label = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Provider = table.Column<int>(type: "integer", nullable: false),
                    Reference = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    Algorithm = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    SizeOrCurve = table.Column<int>(type: "integer", nullable: false),
                    PublicKeyPem = table.Column<string>(type: "text", nullable: false),
                    EncryptedPrivateKeyPem = table.Column<string>(type: "text", nullable: true),
                    Exportable = table.Column<bool>(type: "boolean", nullable: false),
                    OwnerId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    OwnerTeam = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    Environment = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    Purpose = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    CreatedBy = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    DestroyedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LastUsedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ManagedKeys", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ManagedKeys_Label",
                table: "ManagedKeys",
                column: "Label");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ManagedKeys");

            migrationBuilder.DropColumn(
                name: "LastAccessedAt",
                table: "CredentialRefs");

            migrationBuilder.DropColumn(
                name: "LastAccessedBy",
                table: "CredentialRefs");

            migrationBuilder.DropColumn(
                name: "LastRotatedAt",
                table: "CredentialRefs");

            migrationBuilder.DropColumn(
                name: "RotationIntervalDays",
                table: "CredentialRefs");

            migrationBuilder.DropColumn(
                name: "RotationPending",
                table: "CredentialRefs");
        }
    }
}
