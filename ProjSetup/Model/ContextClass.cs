using Microsoft.EntityFrameworkCore;
using ProjSetup.Model;

public class ApplicationDbContext : DbContext
{
    public DbSet<User> Users { get; set; }
    public DbSet<RefreshToken> RefreshTokens { get; set; }

    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);


        builder.Entity<User>().HasIndex(u => u.Username).IsUnique();
        builder.Entity<RefreshToken>().HasKey(rt => rt.Token);
    }
}
