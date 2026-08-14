using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RemoteSSL.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class F21MonitorDueIndex : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateIndex(
                name: "IX_MonitorEndpoints_Enabled_LastProbeAt",
                table: "MonitorEndpoints",
                columns: new[] { "Enabled", "LastProbeAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_MonitorEndpoints_Enabled_LastProbeAt",
                table: "MonitorEndpoints");
        }
    }
}
