using Microsoft.EntityFrameworkCore;
using SecurityApp.ErrorHandling;
using SecurityApp.Repository;
using SecurityApp.Services;
using SecurityApp.Services.Contracts;
using SecurityApp.Services.Entities;
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

            builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

            builder.Services.AddProblemDetails();

            var app = builder.Build();

            app.UseSerilogRequestLogging();

            app.UseExceptionHandler();

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
