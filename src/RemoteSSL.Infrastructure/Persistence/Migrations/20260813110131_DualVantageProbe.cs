using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RemoteSSL.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class DualVantageProbe : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // External probing stays on for every existing monitor; the internal
            // vantage is the opt-in addition.
            migrationBuilder.AddColumn<bool>(
                name: "ExternalProbeEnabled",
                table: "MonitorEndpoints",
                type: "boolean",
                nullable: false,
                defaultValue: true);

            migrationBuilder.AddColumn<string>(
                name: "InternalChainError",
                table: "MonitorEndpoints",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "InternalChainValid",
                table: "MonitorEndpoints",
                type: "boolean",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "InternalHostnameValid",
                table: "MonitorEndpoints",
                type: "boolean",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "InternalObservedVersionId",
                table: "MonitorEndpoints",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "InternalProbeAt",
                table: "MonitorEndpoints",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "InternalProbeError",
                table: "MonitorEndpoints",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "InternalProbeStatus",
                table: "MonitorEndpoints",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "InternalTlsProtocol",
                table: "MonitorEndpoints",
                type: "text",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_MonitorEndpoints_InternalObservedVersionId",
                table: "MonitorEndpoints",
                column: "InternalObservedVersionId");

            migrationBuilder.AddForeignKey(
                name: "FK_MonitorEndpoints_CertificateVersions_InternalObservedVersio~",
                table: "MonitorEndpoints",
                column: "InternalObservedVersionId",
                principalTable: "CertificateVersions",
                principalColumn: "Id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_MonitorEndpoints_CertificateVersions_InternalObservedVersio~",
                table: "MonitorEndpoints");

            migrationBuilder.DropIndex(
                name: "IX_MonitorEndpoints_InternalObservedVersionId",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "ExternalProbeEnabled",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "InternalChainError",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "InternalChainValid",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "InternalHostnameValid",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "InternalObservedVersionId",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "InternalProbeAt",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "InternalProbeError",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "InternalProbeStatus",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "InternalTlsProtocol",
                table: "MonitorEndpoints");
        }
    }
}
