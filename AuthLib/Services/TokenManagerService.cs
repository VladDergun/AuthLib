using AuthLib.Interfaces.Services;
using AuthLib.Options;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OtpNet;
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

        public string GenerateJWTToken(
            string userId,
            string email,
            DateTime? expires = null,
            IReadOnlyList<string>? roles = null,
            IReadOnlyDictionary<string, string>? additionalClaims = null)
        {
            var jwtOptions = _authOptions.JWTOptions;

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.Email, email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            if (additionalClaims != null)
            {
                foreach (var claim in additionalClaims)
                {
                    claims.Add(new Claim(claim.Key, claim.Value));
                }
            }

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

            expires ??= DateTime.UtcNow.Add(_authOptions.TokenOptions.AccessTokenLifetime);

            var token = new JwtSecurityToken(
                issuer: jwtOptions.Issuer,
                audience: jwtOptions.Audience,
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public ClaimsPrincipal? ValidateJWTToken(string token)
        {
            var jwtOptions = _authOptions.JWTOptions;
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(jwtOptions.SigningKey);
            try
            {
                var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = jwtOptions.Issuer,
                    ValidateAudience = true,
                    ValidAudience = jwtOptions.Audience,
                    ValidateLifetime = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuerSigningKey = true,
                }, out SecurityToken validatedToken);
                return principal;
            }
            catch
            {
                return null;
            }
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

        public static string GenerateTwoFactorAuthKey()
        {
            var key = KeyGeneration.GenerateRandomKey(20);

            return Base32Encoding.ToString(key);
        }

        public string HashToken(string token)
        {
            return _authSecurityService.HashToken(token);
        }
    }
}
