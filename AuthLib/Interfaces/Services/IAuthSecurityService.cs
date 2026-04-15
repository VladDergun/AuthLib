namespace AuthLib.Interfaces.Services
{
    public interface IAuthSecurityService
    {
        string HashPassword(string password);
        bool VerifyPassword(string password, string hashedPassword);
        string HashToken(string token);
    }
}
