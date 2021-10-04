using Microsoft.EntityFrameworkCore.Migrations;

namespace AuthnAPI.Migrations
{
    public partial class renamedtoIsUsedpropertyinrefreshtokentable : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "IsUserd",
                table: "RefreshTokens",
                newName: "IsUsed");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "IsUsed",
                table: "RefreshTokens",
                newName: "IsUserd");
        }
    }
}
