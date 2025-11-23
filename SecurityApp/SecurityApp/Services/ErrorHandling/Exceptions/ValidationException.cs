namespace SecurityApp.Services.ErrorHandling.Exceptions;

public class ValidationException : Exception
{
    public int Code { get; set; }

    public ValidationException(string message) : base(message) { }
    public ValidationException(string message, Exception innerException) : base(message, innerException) { }
    public ValidationException(string message, int code) : base(message)
    {
        Code = code;
    }
}
