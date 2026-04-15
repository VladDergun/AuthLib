using AuthLib.Interfaces.Services;
using AuthLib.Options;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthLib.Services
{
    internal sealed class TokenManagerService(
        IOptions<AuthOptions> authOptions,
        IAuthSecurityService authSecurityService) : ITokenManagerService
    {
        private readonly AuthOptions _authOptions = authOptions.Value;
        private readonly IAuthSecurityService _authSecurityService = authSecurityService;

        public string GenerateJWTToken(string userId, string email, IReadOnlyList<string> roles)
        {
            var jwtOptions = _authOptions.JWTOptions;

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.Email, email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            if (roles != null)
            {
                foreach (var role in roles)
                {
                    claims.Add(new Claim("role", role));
                }
            }

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(jwtOptions.SigningKey));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var expires = DateTime.UtcNow.Add(jwtOptions.AccessTokenLifetime);


            var token = new JwtSecurityToken(
                issuer: jwtOptions.Issuer,
                audience: jwtOptions.Audience,
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public (string Token, string TokenHash) GenerateToken()
        {
            var randomBytes = new byte[32];

            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);

            var token = Convert.ToBase64String(randomBytes);

            var hash = _authSecurityService.HashToken(token);

            return (token, hash);
        }

        public string HashToken(string token)
        {
            return _authSecurityService.HashToken(token);
        }
    }
}
