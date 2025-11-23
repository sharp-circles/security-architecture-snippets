namespace SecurityApp.Services.Validations.Contracts
{
    public interface IGetResourceSecurityValidator : ISecurityValidator
    {
        ISecurityValidator WithRequest(int request);
    }
}
