using System.Security.Claims;

namespace AuthLib.Interfaces.Services
{
    public interface ITokenManagerService
    {
        string GenerateJWTToken(string userId, string email, DateTime? expires = null, IReadOnlyList<string>? roles = null, IReadOnlyDictionary<string, string>? additionalClaims = null);
        (string Token, string TokenHash) GenerateToken();
        string HashToken(string token);
        ClaimsPrincipal? ValidateJWTToken(string token);
    }
}
