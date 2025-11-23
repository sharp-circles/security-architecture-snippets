namespace SecurityApp.Services.Validations.Contracts;

public interface ISecurityValidator
{
    ISecurityValidator WithRequest(object request);
    Task ValidateInput();
    Task ValidateBusinessResources();
    Task ValidateBusinessRules();
    Task Validate();
}
