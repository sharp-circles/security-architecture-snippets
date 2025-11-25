using Microsoft.IdentityModel.Tokens;
using SecurityApp.Services.Contracts;
using SecurityApp.Services.Validations.Contracts;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SecurityApp.Services;

public class TokenVendingService
{
    private readonly ILogger<TokenVendingService> _logger;
    private readonly ISecurityRepository<Policy> _policyRepository;
    private readonly ITokenVendingValidator _tokenVendingValidator;

    public TokenVendingService(ILogger<TokenVendingService> logger, ISecurityRepository<Policy> policyRepository, ITokenVendingValidator tokenVendingValidator)
    {
        _logger = logger;
        _policyRepository = policyRepository;
        _tokenVendingValidator = tokenVendingValidator;
    }

    public async Task GenerateToken(string sourceId, string targetId)
    {
        await _tokenVendingValidator.Validate(sourceId, targetId);

        var policy = await _policyRepository.GetResource(1);

        var tokenHandler = new JwtSecurityTokenHandler();

        var key = Encoding.ASCII.GetBytes("My_Super_Secret_Key_For_Signing_Must_Be_32_Bytes!");

        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("sub", sourceId),
                new Claim("scopes", string.Join(" ", policy.Scopes))
            }),
            Audience = targetId,
            Issuer = "TokenVendorMachine",
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);

        _logger.LogInformation("Token mint generated for {SourceId} > {TargetId}. Expires: {Expiration}", sourceId, targetId, tokenDescriptor.Expires);

        return tokenHandler.WriteToken(token);
    }
}

public class Policy
{
    public string SourceId { get; set; }
    public string TargetId { get; set; }
    public string[] Scopes { get; set; }
}
