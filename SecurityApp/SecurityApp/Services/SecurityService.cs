using SecurityApp.Services.Contracts;
using SecurityApp.Services.Dto;

namespace SecurityApp.Services;

public class SecurityService : ISecurityService
{
    private readonly ISecurityRepository _securityRepository;

    public SecurityService(ISecurityRepository securityRepository)
    {
        _securityRepository = securityRepository;
    }

    public async Task<ResourceDto> GetResource(int id)
    {
        var resource = await _securityRepository.GetResource(id);

        return new ResourceDto()
        {
            UserId = resource.UserId,
            ResourceName = resource.ResourceName,
            TenantId = resource.TenantId
        };
    }
}
