using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RemoteSSL.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class StrategyAndWinRm : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "MaxConcurrency",
                table: "DeploymentJobs",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<bool>(
                name: "StopOnFailure",
                table: "DeploymentJobs",
                type: "boolean",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "MaxConcurrency",
                table: "DeploymentJobs");

            migrationBuilder.DropColumn(
                name: "StopOnFailure",
                table: "DeploymentJobs");
        }
    }
}
