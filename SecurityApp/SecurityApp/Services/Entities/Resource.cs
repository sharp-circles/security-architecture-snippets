using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SecurityApp.Services.Entities;

[Table("Resource")]
public class Resource
{
    [Key]
    public int UserId { get; set; }
    public string ResourceName { get; set; }
    public int TenantId { get; set; }
}
