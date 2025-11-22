namespace SecurityApp.Services.Contracts;

public record ResourceDto
{
    public int UserId { get; set; }
    public string ResourceName { get; set; }
    public int TenantId { get; set; }
}
