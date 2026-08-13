using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace RemoteSSL.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class DeploymentOperationsAndIdempotency : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "HaRole",
                table: "Targets",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "ManualContinuation",
                table: "DeploymentJobs",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<Guid>(
                name: "RolledBackFromJobId",
                table: "DeploymentJobs",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "IdempotencyRecords",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Key = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Endpoint = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    RequestFingerprint = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    StatusCode = table.Column<int>(type: "integer", nullable: false),
                    ResponseJson = table.Column<string>(type: "text", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IdempotencyRecords", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_IdempotencyRecords_CreatedAt",
                table: "IdempotencyRecords",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_IdempotencyRecords_Key_Endpoint",
                table: "IdempotencyRecords",
                columns: new[] { "Key", "Endpoint" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "IdempotencyRecords");

            migrationBuilder.DropColumn(
                name: "HaRole",
                table: "Targets");

            migrationBuilder.DropColumn(
                name: "ManualContinuation",
                table: "DeploymentJobs");

            migrationBuilder.DropColumn(
                name: "RolledBackFromJobId",
                table: "DeploymentJobs");
        }
    }
}
