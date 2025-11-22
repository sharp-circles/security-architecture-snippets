using Microsoft.EntityFrameworkCore;
using SecurityApp.Repository;
using SecurityApp.Repository.Models;

namespace SecurityApp
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddDbContext<ResourceContext>(options => options.UseInMemoryDatabase(nameof(Resource)));

            builder.Services.AddControllers();

            var app = builder.Build();

            app.UseHttpsRedirection();

            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }
    }
}
