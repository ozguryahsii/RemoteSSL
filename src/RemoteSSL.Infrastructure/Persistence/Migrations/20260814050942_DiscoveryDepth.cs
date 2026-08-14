using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RemoteSSL.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class DiscoveryDepth : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "HealthCheckAt",
                table: "MonitorEndpoints",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "HealthCheckDetail",
                table: "MonitorEndpoints",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "HealthCheckExpectedStatus",
                table: "MonitorEndpoints",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "HealthCheckLatencyMs",
                table: "MonitorEndpoints",
                type: "integer",
                nullable: true);

            // Existing monitors have no health check configured; the entity default must hold
            // for them too, otherwise the screen would show an empty status.
            migrationBuilder.AddColumn<string>(
                name: "HealthCheckStatus",
                table: "MonitorEndpoints",
                type: "text",
                nullable: false,
                defaultValue: "NotConfigured");

            migrationBuilder.AddColumn<string>(
                name: "HealthCheckUrl",
                table: "MonitorEndpoints",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "InternalCipherSuite",
                table: "MonitorEndpoints",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LastCipherSuite",
                table: "MonitorEndpoints",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Protocol",
                table: "MonitorEndpoints",
                type: "text",
                nullable: false,
                defaultValue: "tls");

            migrationBuilder.AddColumn<int>(
                name: "RetryCount",
                table: "MonitorEndpoints",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "TimeoutSeconds",
                table: "MonitorEndpoints",
                type: "integer",
                nullable: true);

            // Links that already exist came from a real handshake observation, so they carry
            // full confidence — defaulting them to 0 would misrepresent settled correlations.
            migrationBuilder.AddColumn<int>(
                name: "Confidence",
                table: "MonitorCertificateLinks",
                type: "integer",
                nullable: false,
                defaultValue: 100);

            migrationBuilder.AddColumn<string>(
                name: "CaIssuerUrlsJson",
                table: "CertificateVersions",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "CrlDistributionPointsJson",
                table: "CertificateVersions",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "ExtendedKeyUsagesJson",
                table: "CertificateVersions",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<bool>(
                name: "IsCertificateAuthority",
                table: "CertificateVersions",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "KeyUsagesJson",
                table: "CertificateVersions",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "OcspUrlsJson",
                table: "CertificateVersions",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<int>(
                name: "PathLengthConstraint",
                table: "CertificateVersions",
                type: "integer",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "HealthCheckAt",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "HealthCheckDetail",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "HealthCheckExpectedStatus",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "HealthCheckLatencyMs",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "HealthCheckStatus",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "HealthCheckUrl",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "InternalCipherSuite",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "LastCipherSuite",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "Protocol",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "RetryCount",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "TimeoutSeconds",
                table: "MonitorEndpoints");

            migrationBuilder.DropColumn(
                name: "Confidence",
                table: "MonitorCertificateLinks");

            migrationBuilder.DropColumn(
                name: "CaIssuerUrlsJson",
                table: "CertificateVersions");

            migrationBuilder.DropColumn(
                name: "CrlDistributionPointsJson",
                table: "CertificateVersions");

            migrationBuilder.DropColumn(
                name: "ExtendedKeyUsagesJson",
                table: "CertificateVersions");

            migrationBuilder.DropColumn(
                name: "IsCertificateAuthority",
                table: "CertificateVersions");

            migrationBuilder.DropColumn(
                name: "KeyUsagesJson",
                table: "CertificateVersions");

            migrationBuilder.DropColumn(
                name: "OcspUrlsJson",
                table: "CertificateVersions");

            migrationBuilder.DropColumn(
                name: "PathLengthConstraint",
                table: "CertificateVersions");
        }
    }
}
