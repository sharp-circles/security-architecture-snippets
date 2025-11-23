using SecurityApp.Services.Contracts;
using SecurityApp.Services.Entities;
using SecurityApp.Services.ErrorHandling.Exceptions;
using SecurityApp.Services.Validations.Contracts;

namespace SecurityApp.Services.Validations;

public class GetResourceSecurityValidator : IGetResourceSecurityValidator
{
    private readonly ISecurityRepository<Resource> _securityRepository;
    private int _resourceId;

    public GetResourceSecurityValidator(ISecurityRepository<Resource> securityRepository)
    {
        _securityRepository = securityRepository;
    }

    public ISecurityValidator WithRequest(int request)
    {
        _resourceId = request;

        return this;
    }

    public async Task Validate()
    {
        await ValidateInput();
        await ValidateBusinessResources();
        await ValidateBusinessRules();
    }

    public Task ValidateInput()
    {
        var validation = _resourceId > 0 && _resourceId < int.MaxValue;

        if (!validation)
        {
            throw new ValidationException("Id must be greater than 0", StatusCodes.Status400BadRequest);
        }

        return Task.CompletedTask;
    }

    public async Task ValidateBusinessResources()
    {
        var resource = await _securityRepository.GetResource(_resourceId);

        if (resource == null)
        {
            throw new ValidationException("Resource not found with provided id", StatusCodes.Status404NotFound);
        }
    }

    public Task ValidateBusinessRules()
    {
        return Task.CompletedTask;
    }
}
