namespace SecurityApp.Services.ErrorHandling.Exceptions;

public class SecurityAppException : Exception
{
    public int Code { get; set; }

    public SecurityAppException(string message) : base(message) { }
    public SecurityAppException(string message, Exception innerException) : base(message, innerException) { }
    public SecurityAppException(string message, int code) : base(message)
    {
        Code = code;
    }
}
