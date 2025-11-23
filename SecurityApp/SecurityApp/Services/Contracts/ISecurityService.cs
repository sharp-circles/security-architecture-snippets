using SecurityApp.Services.Dto;

namespace SecurityApp.Services.Contracts;

public interface ISecurityService
{
    Task<ResourceDto> GetResource(int id);
}
