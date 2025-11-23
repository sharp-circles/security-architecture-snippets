using Microsoft.EntityFrameworkCore;
using SecurityApp.Repository.Entities;

namespace SecurityApp.Repository;

public class ResourceContext : DbContext
{
    public DbSet<Resource> Resources { get; set; }

    public ResourceContext(DbContextOptions<ResourceContext> options) : base(options)
    {
        base.Database.EnsureCreatedAsync();
    }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        optionsBuilder.UseAsyncSeeding(async (context, _, cancellationToken) =>
        {
            context.Add(new Resource() { UserId = 1, ResourceName = "Resource", TenantId = 1 });

            await context.SaveChangesAsync(cancellationToken);
        });
    }
}
