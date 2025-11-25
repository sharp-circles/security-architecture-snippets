namespace SecurityApp.Services.Validations.Contracts;

public interface ITokenVendingValidator : ISecurityValidator
{
    Task Validate(string sourceId, string targetId);
}
