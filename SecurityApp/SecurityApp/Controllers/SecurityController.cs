using Microsoft.AspNetCore.Mvc;
using SecurityApp.Services.Contracts;

namespace SecurityApp.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class SecurityController : ControllerBase
{
    private readonly ISecurityService _securityService;

    public SecurityController(ISecurityService securityService)
    {
        _securityService = securityService;
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
