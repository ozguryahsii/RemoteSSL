using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RemoteSSL.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class SecurityIdentityAndScopes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ExternalSubject",
                table: "Users",
                type: "text",
                nullable: true);

            // Existing users have no scope rules, which means "roles alone decide" — an empty
            // string would parse to nothing and read as a malformed value instead.
            migrationBuilder.AddColumn<string>(
                name: "ScopesJson",
                table: "Users",
                type: "text",
                nullable: false,
                defaultValue: "[]");

            migrationBuilder.AddColumn<string>(
                name: "TargetGroup",
                table: "Targets",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "AdapterVersionsJson",
                table: "Runners",
                type: "text",
                nullable: false,
                defaultValue: "{}");

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "IdentityRevokedAt",
                table: "Runners",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "IdentityRevokedReason",
                table: "Runners",
                type: "text",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "RunnerAuthorities",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CertificatePem = table.Column<string>(type: "text", nullable: false),
                    EncryptedKeyPem = table.Column<string>(type: "text", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RunnerAuthorities", x => x.Id);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "RunnerAuthorities");

            migrationBuilder.DropColumn(
                name: "ExternalSubject",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "ScopesJson",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "TargetGroup",
                table: "Targets");

            migrationBuilder.DropColumn(
                name: "AdapterVersionsJson",
                table: "Runners");

            migrationBuilder.DropColumn(
                name: "IdentityRevokedAt",
                table: "Runners");

            migrationBuilder.DropColumn(
                name: "IdentityRevokedReason",
                table: "Runners");
        }
    }
}
