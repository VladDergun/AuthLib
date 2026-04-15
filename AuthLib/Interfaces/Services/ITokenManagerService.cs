namespace AuthLib.Interfaces.Services
{
    public interface ITokenManagerService
    {
        string GenerateJWTToken(string userId, string email, IReadOnlyList<string> roles);
        (string Token, string TokenHash) GenerateToken();
        string HashToken(string token);
    }
}
