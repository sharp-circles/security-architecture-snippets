using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SecurityApp.Repository.Models;

[Table("Resource")]
public class Resource
{
    [Key]
    public int UserId { get; set; }
    public string ResourceName { get; set; }
    public int TenantId { get; set; }
}
