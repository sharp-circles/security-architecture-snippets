using SecurityApp.Services.Contracts;

namespace SecurityApp.Repository;

public class SecurityRepository<T> : ISecurityRepository<T> where T : class
{
    private readonly SecurityContext _context;

    public SecurityRepository(SecurityContext context)
    {
        _context = context;
    }

    public async Task<T> GetResource(int id)
    {
        return await _context.FindAsync<T>(id);
    }
}
