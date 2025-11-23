using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using SecurityApp.Services.ErrorHandling.Exceptions;

namespace SecurityApp.Services.ErrorHandling;

public class GlobalExceptionHandler : IExceptionHandler
{
    private readonly ILogger<GlobalExceptionHandler> _logger;

    public GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger)
    {
        _logger = logger;
    }

    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        var problemDetails = exception switch
        {
            UnauthorizedAccessException => HandleUnauthorizedException(exception),
            ValidationException => HandleValidationException(exception),
            _ => HandleUnhandledException(exception)
        };

        if (problemDetails.Status != null)
        {
            httpContext.Response.StatusCode = problemDetails.Status.Value;
        }

        await httpContext.Response.WriteAsJsonAsync(problemDetails, cancellationToken);

        return true;
    }

    private ProblemDetails HandleUnauthorizedException(Exception exception)
    {
        _logger.LogError("Exception was thrown: {Message}", exception.Message);

        return new ProblemDetails()
        {
            Status = StatusCodes.Status401Unauthorized,
            Title = "Unauthorized"
        };
    }

    private ProblemDetails HandleUnhandledException(Exception exception)
    {
        _logger.LogError("Exception was thrown: {Message}", exception.Message);

        return new ProblemDetails()
        {
            Status = StatusCodes.Status500InternalServerError,
            Title = "Unhandled exception"
        };
    }

    private ProblemDetails HandleValidationException(Exception exception)
    {
        _logger.LogError("Exception was thrown: {Message}", exception.Message);

        var validationException = (ValidationException)exception;

        return new ProblemDetails()
        {
            Status = validationException.Code,
            Title = validationException.Message
        };
    }
}
