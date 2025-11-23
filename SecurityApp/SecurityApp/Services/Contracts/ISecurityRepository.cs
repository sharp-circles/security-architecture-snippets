using SecurityApp.Services.Entities;

namespace SecurityApp.Services.Contracts;

public interface ISecurityRepository
{
    Task<Resource> GetResource(int id);
}
