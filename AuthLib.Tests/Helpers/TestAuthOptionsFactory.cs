using AuthLib.Options;
using Microsoft.Extensions.Options;

namespace AuthLib.Tests.Helpers
{
    public static class TestAuthOptionsFactory
    {
        public static IOptions<AuthOptions> Create(
            bool emailVerificationRequired = false,
            TwoFactorAuthOptions? twoFactorAuthOptions = null)
        {
            var options = new AuthOptions
            {
                PasswordSecret = "test-password-secret-for-testing-purposes",
                TokenSecret = "test-token-secret-for-testing-purposes",
                EmailVerificationRequired = emailVerificationRequired,
                Roles = new List<Role>
                {
                    new() { Name = "User", IsDefault = true },
                    new() { Name = "Admin", IsDefault = false },
                    new() { Name = "Moderator", IsDefault = false }
                },
                JWTOptions = new JWTOptions
                {
                    Issuer = "TestIssuer",
                    Audience = "TestAudience",
                    SigningKey = "super-secret-key-for-testing-at-least-32-characters-long",
                    AccessTokenLifetime = TimeSpan.FromMinutes(15),
                    RefreshTokenLifetime = TimeSpan.FromDays(7),
                    EmailVerificationTokenLifetime = TimeSpan.FromDays(1),
                    PasswordResetTokenLifetime = TimeSpan.FromMinutes(30)
                },
                PasswordOptions = new PasswordOptions
                {
                    RequireMinLength = 6,
                    RequireMaxLength = 100,
                    RequireDigitCount = 0,
                    RequireLowercaseCount = 0,
                    RequireUppercaseCount = 0,
                    RequireNonAlphanumericCount = 0
                },
                TokenCleanupOptions = new TokenCleanupOptions
                {
                    Enabled = false
                },
                TwoFactorAuthOptions = twoFactorAuthOptions
            };

            return Microsoft.Extensions.Options.Options.Create(options);
        }
    }
}
