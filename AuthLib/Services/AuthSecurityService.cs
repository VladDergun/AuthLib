using AuthLib.Interfaces.Services;
using AuthLib.Options;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;

namespace AuthLib.Services
{
    internal sealed class AuthSecurityService(IOptions<AuthOptions> options) : IAuthSecurityService
    {
        private readonly AuthOptions _options = options.Value;

        public string HashPassword(string password)
        {
            string hash = BCrypt.Net.BCrypt.HashPassword(password + _options.PasswordSecret);
            return hash;
        }

        public bool VerifyPassword(string password, string hashedPassword)
        {
            return BCrypt.Net.BCrypt.Verify(password + _options.PasswordSecret, hashedPassword);
        }

        public string HashToken(string token)
        {
            var keyBytes = Encoding.UTF8.GetBytes(_options.TokenSecret);
            var tokenBytes = Encoding.UTF8.GetBytes(token);

            using var hmac = new HMACSHA256(keyBytes);
            var hashBytes = hmac.ComputeHash(tokenBytes);

            return Convert.ToBase64String(hashBytes);
        }
    }
}
