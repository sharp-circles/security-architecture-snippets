using SecurityApp.Services.Contracts;
using SecurityApp.Services.Dto;

namespace SecurityApp.Services;

public class SecurityService : ISecurityService
{
    private readonly ISecurityRepository _securityRepository;
    private readonly ILogger<SecurityService> _logger;

    public SecurityService(ISecurityRepository securityRepository, ILogger<SecurityService> logger)
    {
        _securityRepository = securityRepository;
        _logger = logger;
    }

    public async Task<ResourceDto> GetResource(int id)
    {
        _logger.LogInformation("Processing get resource with id {Id}", id);

        var resource = await _securityRepository.GetResource(id);

        return new ResourceDto()
        {
            UserId = resource.UserId,
            ResourceName = resource.ResourceName,
            TenantId = resource.TenantId
        };
    }
}
