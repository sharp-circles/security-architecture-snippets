using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace SecurityApp.Authentication;

[ApiController]
[Route("api/v1/[controller]")]
public class AuthenticationController : ControllerBase
{
    [HttpGet("authenticate")]
    public ActionResult Authenticate()
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var issuerSigningKey = "HcEwxbir187d3zxFBJmX6tx0B240Os2B"u8.ToArray();

        var claims = new List<Claim>()
        {
            new(JwtRegisteredClaimNames.Name, "user1"),
            new(JwtRegisteredClaimNames.Email, "user1@gmail.com"),
            new("role", "admin"),
        };

        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(30),
            Issuer = "http://localhost:7049",
            Audience = "http://localhost:7049",
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(issuerSigningKey), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);

        return new OkObjectResult(tokenHandler.WriteToken(token));
    }
}
