using Microsoft.AspNetCore.Mvc;

namespace SecurityApp.Controllers;

[ApiController]
[Route("api/v1/[controller]")]
public class SecurityController : ControllerBase
{
    public SecurityController()
    {

    }

    [HttpGet("resource/{id}")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> GetResource(int id)
    {

    }
}
