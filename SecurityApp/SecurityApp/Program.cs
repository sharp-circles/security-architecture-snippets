using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SecurityApp.Repository;
using SecurityApp.Services;
using SecurityApp.Services.Contracts;
using SecurityApp.Services.Entities;
using SecurityApp.Services.ErrorHandling;
using SecurityApp.Services.Validations;
using SecurityApp.Services.Validations.Contracts;
using Serilog;

namespace SecurityApp
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            ReadLoggerConfiguration();

            builder.Services.AddDbContext<SecurityContext>(options => options.UseInMemoryDatabase(nameof(Resource)));

            builder.Services.AddAuthorization();
            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                            .AddJwtBearer(x =>
                            {
                                x.TokenValidationParameters = new TokenValidationParameters()
                                {
                                    IssuerSigningKey = new SymmetricSecurityKey("HcEwxbir187d3zxFBJmX6tx0B240Os2B"u8.ToArray()),
                                    ValidIssuer = "http://localhost:7049",
                                    ValidAudience = "http://localhost:7049",
                                    ValidateIssuerSigningKey = true,
                                    ValidateLifetime = true,
                                    ValidateIssuer = true,
                                    ValidateAudience = true
                                };
                            });

            builder.Services.AddScoped<ISecurityService, SecurityService>();
            builder.Services.AddScoped<ISecurityRepository<Resource>, SecurityRepository<Resource>>();
            builder.Services.AddScoped<IGetResourceSecurityValidator, GetResourceSecurityValidator>();

            builder.Services.AddSerilog();

            builder.Services.AddControllers();

            builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

            builder.Services.AddProblemDetails();

            var app = builder.Build();

            app.UseSerilogRequestLogging();

            app.UseExceptionHandler();

            app.UseHttpsRedirection();

            app.UseAuthentication();
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
