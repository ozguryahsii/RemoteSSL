using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RemoteSSL.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class F18AuditIntegrity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "Result",
                table: "AuditEvents",
                type: "character varying(64)",
                maxLength: 64,
                nullable: false,
                oldClrType: typeof(string),
                oldType: "text");

            migrationBuilder.AlterColumn<string>(
                name: "ObjectId",
                table: "AuditEvents",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "text",
                oldNullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ApprovalReference",
                table: "AuditEvents",
                type: "character varying(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "ArchivedAt",
                table: "AuditEvents",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Hash",
                table: "AuditEvents",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "NewFingerprint",
                table: "AuditEvents",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "OldFingerprint",
                table: "AuditEvents",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PreviousHash",
                table: "AuditEvents",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "SealedAt",
                table: "AuditEvents",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "Sequence",
                table: "AuditEvents",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<string>(
                name: "SessionId",
                table: "AuditEvents",
                type: "character varying(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SourceIp",
                table: "AuditEvents",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "UserAgent",
                table: "AuditEvents",
                type: "character varying(512)",
                maxLength: 512,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_AuditEvents_Action",
                table: "AuditEvents",
                column: "Action");

            migrationBuilder.CreateIndex(
                name: "IX_AuditEvents_Actor",
                table: "AuditEvents",
                column: "Actor");

            migrationBuilder.CreateIndex(
                name: "IX_AuditEvents_Sequence",
                table: "AuditEvents",
                column: "Sequence");

            // §25.3 / ADR-007 append-only enforcement at the database itself, so a compromised
            // application account still cannot rewrite history. Content columns are frozen once
            // written; the sealing pass may only fill in the chain columns, and deletion is
            // refused unless the retention job has declared itself for the transaction.
            migrationBuilder.Sql("""
                CREATE OR REPLACE FUNCTION remotessl_audit_append_only() RETURNS trigger AS $$
                BEGIN
                    IF TG_OP = 'DELETE' THEN
                        IF current_setting('remotessl.audit_retention', true) IS DISTINCT FROM 'on' THEN
                            RAISE EXCEPTION 'AuditEvents is append-only; rows are removed only by the retention job';
                        END IF;
                        RETURN OLD;
                    END IF;

                    IF NEW."Id"          IS DISTINCT FROM OLD."Id"
                    OR NEW."Timestamp"   IS DISTINCT FROM OLD."Timestamp"
                    OR NEW."Actor"       IS DISTINCT FROM OLD."Actor"
                    OR NEW."Action"      IS DISTINCT FROM OLD."Action"
                    OR NEW."ObjectType"  IS DISTINCT FROM OLD."ObjectType"
                    OR NEW."ObjectId"    IS DISTINCT FROM OLD."ObjectId"
                    OR NEW."TargetId"    IS DISTINCT FROM OLD."TargetId"
                    OR NEW."Result"      IS DISTINCT FROM OLD."Result"
                    OR NEW."CorrelationId"     IS DISTINCT FROM OLD."CorrelationId"
                    OR NEW."DetailsJson"       IS DISTINCT FROM OLD."DetailsJson"
                    OR NEW."SessionId"         IS DISTINCT FROM OLD."SessionId"
                    OR NEW."SourceIp"          IS DISTINCT FROM OLD."SourceIp"
                    OR NEW."UserAgent"         IS DISTINCT FROM OLD."UserAgent"
                    OR NEW."ApprovalReference" IS DISTINCT FROM OLD."ApprovalReference"
                    OR NEW."OldFingerprint"    IS DISTINCT FROM OLD."OldFingerprint"
                    OR NEW."NewFingerprint"    IS DISTINCT FROM OLD."NewFingerprint"
                    THEN
                        RAISE EXCEPTION 'AuditEvents is append-only; audited content cannot be modified';
                    END IF;

                    IF OLD."Hash" IS NOT NULL AND NEW."Hash" IS DISTINCT FROM OLD."Hash" THEN
                        RAISE EXCEPTION 'A sealed audit row cannot be re-sealed';
                    END IF;

                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql;
                """);

            migrationBuilder.Sql("""
                DROP TRIGGER IF EXISTS remotessl_audit_append_only_trg ON "AuditEvents";
                CREATE TRIGGER remotessl_audit_append_only_trg
                    BEFORE UPDATE OR DELETE ON "AuditEvents"
                    FOR EACH ROW EXECUTE FUNCTION remotessl_audit_append_only();
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                DROP TRIGGER IF EXISTS remotessl_audit_append_only_trg ON "AuditEvents";
                DROP FUNCTION IF EXISTS remotessl_audit_append_only();
                """);

            migrationBuilder.DropIndex(
                name: "IX_AuditEvents_Action",
                table: "AuditEvents");

            migrationBuilder.DropIndex(
                name: "IX_AuditEvents_Actor",
                table: "AuditEvents");

            migrationBuilder.DropIndex(
                name: "IX_AuditEvents_Sequence",
                table: "AuditEvents");

            migrationBuilder.DropColumn(
                name: "ApprovalReference",
                table: "AuditEvents");

            migrationBuilder.DropColumn(
                name: "ArchivedAt",
                table: "AuditEvents");

            migrationBuilder.DropColumn(
                name: "Hash",
                table: "AuditEvents");

            migrationBuilder.DropColumn(
                name: "NewFingerprint",
                table: "AuditEvents");

            migrationBuilder.DropColumn(
                name: "OldFingerprint",
                table: "AuditEvents");

            migrationBuilder.DropColumn(
                name: "PreviousHash",
                table: "AuditEvents");

            migrationBuilder.DropColumn(
                name: "SealedAt",
                table: "AuditEvents");

            migrationBuilder.DropColumn(
                name: "Sequence",
                table: "AuditEvents");

            migrationBuilder.DropColumn(
                name: "SessionId",
                table: "AuditEvents");

            migrationBuilder.DropColumn(
                name: "SourceIp",
                table: "AuditEvents");

            migrationBuilder.DropColumn(
                name: "UserAgent",
                table: "AuditEvents");

            migrationBuilder.AlterColumn<string>(
                name: "Result",
                table: "AuditEvents",
                type: "text",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "character varying(64)",
                oldMaxLength: 64);

            migrationBuilder.AlterColumn<string>(
                name: "ObjectId",
                table: "AuditEvents",
                type: "text",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "character varying(256)",
                oldMaxLength: 256,
                oldNullable: true);
        }
    }
}
