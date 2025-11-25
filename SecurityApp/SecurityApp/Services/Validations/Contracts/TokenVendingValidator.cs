

using SecurityApp.Services.Contracts;
using SecurityApp.Services.ErrorHandling.Exceptions;

namespace SecurityApp.Services.Validations.Contracts;

public class TokenVendingValidator : ITokenVendingValidator
{
    private readonly ISecurityRepository<Policy> _policyRepository;

    private string _sourceId;
    private string _targetId;

    public TokenVendingValidator(ISecurityRepository<Policy> policyRepository)
    {
        _policyRepository = policyRepository;
    }

    public async Task Validate(string sourceId, string targetId)
    {
        _sourceId = sourceId;
        _targetId = targetId;

        await ValidateInput();
        await ValidateBusinessResources();
        await ValidateBusinessRules();
    }

    public Task ValidateInput()
    {
        CheckIdsNotEmpty();
        // CheckInLength();
        // CheckPatterns();

        return Task.CompletedTask;
    }

    private void CheckIdsNotEmpty()
    {
        var validation = !string.IsNullOrWhiteSpace(_sourceId) && !string.IsNullOrWhiteSpace(_targetId);

        if (!validation)
        {
            throw new ValidationException("Ids cannot be empty", StatusCodes.Status400BadRequest);
        }
    }

    public async Task ValidateBusinessResources()
    {
        var policy = await _policyRepository.GetResource(1);

        if (policy == null)
        {
            // Security exception -> 403
            throw new ValidationException("Policy not found for given ids", StatusCodes.Status403Forbidden);
        }
    }

    public Task ValidateBusinessRules()
    {
        return Task.CompletedTask;
    }
}
