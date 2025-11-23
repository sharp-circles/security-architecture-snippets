using SecurityApp.Services.Contracts;
using SecurityApp.Services.Dto;
using SecurityApp.Services.Entities;
using SecurityApp.Services.ErrorHandling.Exceptions;
using SecurityApp.Services.Validations.Contracts;

namespace SecurityApp.Services;

public class SecurityService : ISecurityService
{
    private readonly ISecurityRepository<Resource> _securityRepository;
    private readonly IGetResourceSecurityValidator _securityValidator;
    private readonly ILogger<SecurityService> _logger;

    public SecurityService(ISecurityRepository<Resource> securityRepository, IGetResourceSecurityValidator securityValidator, ILogger<SecurityService> logger)
    {
        _securityRepository = securityRepository;
        _securityValidator = securityValidator;
        _logger = logger;
    }

    public async Task<ResourceDto> GetResource(int id)
    {
        try
        {
            await _securityValidator.WithRequest(id)
                        .Validate();

            _logger.LogInformation("Processing get resource with id {Id}", id);

            var resource = await _securityRepository.GetResource(id);

            return new ResourceDto()
            {
                UserId = resource.UserId,
                ResourceName = resource.ResourceName,
                TenantId = resource.TenantId
            };
        }
        catch (Exception)
        {
            throw new SecurityAppException("Unexpected error while getting resource");
        }
    }
}
