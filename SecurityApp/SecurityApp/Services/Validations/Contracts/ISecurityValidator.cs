namespace SecurityApp.Services.Validations.Contracts;

public interface ISecurityValidator
{
    Task ValidateInput();
    Task ValidateBusinessResources();
    Task ValidateBusinessRules();
    Task Validate();
}
