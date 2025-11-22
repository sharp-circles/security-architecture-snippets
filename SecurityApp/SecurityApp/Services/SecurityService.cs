using SecurityApp.Repository;
using SecurityApp.Services.Contracts;

namespace SecurityApp.Services;

public class SecurityService
{
    private readonly SecurityRepository _securityRepository;

    public SecurityService(ResourceContext context)
    {
        _securityRepository = new SecurityRepository(context);
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
