using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using TestApiJwt.Models.Config;

namespace TestApiJwt.Models;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> opations)
        : base(opations)
    {

    }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        base.OnConfiguring(optionsBuilder);

        optionsBuilder.ConfigureWarnings(warnings =>
               warnings.Ignore(RelationalEventId.PendingModelChangesWarning));
    }


    protected override void OnModelCreating(ModelBuilder builder)
    {
          base.OnModelCreating(builder);
        //builder.Entity<ApplicationUser>().ToTable("Users", "Security");
        //builder.Entity<IdentityRole>().ToTable("Roles", "Security");
        //builder.Entity<IdentityUserRole<string>>().ToTable("UserRoles", "Security");
        //builder.Entity<IdentityUserClaim<string>>().ToTable("UserClaims", "Security");
        //builder.Entity<IdentityUserLogin<string>>().ToTable("UserLogins", "Security");
        //builder.Entity<IdentityRoleClaim<string>>().ToTable("RoleClaims", "Security");
        //builder.Entity<IdentityUserToken<string>>().ToTable("UserTokens", "Security");

        builder.ApplyConfiguration(new IdentityRoleConfiguraiton());
    }
}