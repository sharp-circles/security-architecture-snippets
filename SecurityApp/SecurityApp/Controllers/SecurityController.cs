using Microsoft.AspNetCore.Mvc;
using SecurityApp.Repository;
using SecurityApp.Services;

namespace SecurityApp.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class SecurityController : ControllerBase
{
    private readonly SecurityService _securityService;

    public SecurityController(ResourceContext context)
    {
        _securityService = new SecurityService(context);
    }

    [HttpGet("resource/{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> GetResource(int id)
    {
        var resource = await _securityService.GetResource(id);

        return new OkObjectResult(resource);
    }
}
