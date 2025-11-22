using SecurityApp.Repository.Models;

namespace SecurityApp.Repository;

public class SecurityRepository
{
    private readonly ResourceContext _context;

    public SecurityRepository(ResourceContext context)
    {
        _context = context;
    }

    public async Task<Resource> GetResource(int id)
    {
        return await _context.FindAsync<Resource>(id);
    }
}
