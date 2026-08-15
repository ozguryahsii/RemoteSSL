using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RemoteSSL.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class F25ExpiryScanAndScopeDimensions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "RetryCount",
                table: "DeploymentJobs",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "BusinessUnit",
                table: "Certificates",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "LastExpiryAlertThreshold",
                table: "Certificates",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TagsJson",
                table: "Certificates",
                type: "text",
                nullable: false,
                // An empty string is not valid JSON; existing rows must read back as an empty array.
                defaultValue: "[]");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "RetryCount",
                table: "DeploymentJobs");

            migrationBuilder.DropColumn(
                name: "BusinessUnit",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "LastExpiryAlertThreshold",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "TagsJson",
                table: "Certificates");
        }
    }
}
