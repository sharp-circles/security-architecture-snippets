namespace SecurityApp.Services.Contracts;

public interface ISecurityRepository<T>
{
    Task<T> GetResource(int id);
}
