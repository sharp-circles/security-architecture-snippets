using Microsoft.EntityFrameworkCore;
using SecurityApp.Repository;
using SecurityApp.Repository.Entities;
using SecurityApp.Services;
using SecurityApp.Services.Contracts;
using Serilog;

namespace SecurityApp
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            ReadLoggerConfiguration();

            builder.Services.AddDbContext<ResourceContext>(options => options.UseInMemoryDatabase(nameof(Resource)));

            builder.Services.AddScoped<ISecurityService, SecurityService>();
            builder.Services.AddScoped<ISecurityRepository, SecurityRepository>();

            builder.Services.AddSerilog();

            builder.Services.AddControllers();

            var app = builder.Build();

            app.UseSerilogRequestLogging();

            app.UseHttpsRedirection();

            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }

        public static void ReadLoggerConfiguration()
        {
            Log.Logger = new LoggerConfiguration().ReadFrom.Configuration(new ConfigurationBuilder()
                                                           .AddJsonFile("appsettings.json")
                                                           .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"}.json", optional: true)
                                                           .AddEnvironmentVariables()
                                                           .Build())
                                                           .Enrich.FromLogContext()
                                                           .CreateLogger();
        }
    }
}
