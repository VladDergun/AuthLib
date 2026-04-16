using System.Text.RegularExpressions;

namespace AuthLib.Options
{
    /// <summary>
    /// Main configuration options for the authentication library.
    /// </summary>
    public sealed class AuthOptions
    {
        /// <summary>
        /// Secret key used for password hashing operations. This should be a strong, randomly generated value.
        /// </summary>
        public required string PasswordSecret { get; set; }
        /// <summary>
        /// Secret key used for token generation and validation. This should be a strong, randomly generated value.
        /// </summary>
        public required string TokenSecret { get; set; }
        /// <summary>
        /// Indicates whether email verification is required for user registration. Default is false.
        /// </summary>
        public bool EmailVerificationRequired { get; set; } = false;
        /// <summary>
        /// List of roles available in the authentication system. Define roles and their default assignment behavior.
        /// </summary>
        public required List<Role> Roles { get; set; }
        /// <summary>
        /// JWT (JSON Web Token) configuration options including issuer, audience, signing key, and token lifetimes.
        /// </summary>
        public required JWTOptions JWTOptions { get; set; }
        /// <summary>
        /// Password validation and complexity requirements configuration.
        /// </summary>
        public PasswordOptions? PasswordOptions { get; set; }
        /// <summary>
        /// Configuration for automatic cleanup of expired tokens from the database.
        /// </summary>
        public TokenCleanupOptions? TokenCleanupOptions { get; set; }
        /// <summary>
        /// Configuration options for two-factor authentication (2FA), including issuer information for 2FA token generation.
        /// </summary>
        public TwoFactorAuthOptions? TwoFactorAuthOptions { get; set; }
    }

    /// <summary>
    /// Represents a role in the authentication system.
    /// </summary>
    public sealed class Role
    {
        /// <summary>
        /// The name of the role.
        /// </summary>
        public required string Name { get; set; }
        /// <summary>
        /// Indicates whether this role should be automatically assigned to new users. Default is false.
        /// </summary>
        public required bool IsDefault { get; set; }
    }

    /// <summary>
    /// JWT (JSON Web Token) configuration options.
    /// </summary>
    public sealed class JWTOptions
    {
        /// <summary>
        /// The issuer claim (iss) identifies the principal that issued the JWT.
        /// </summary>
        public required string Issuer { get; set; }
        /// <summary>
        /// The audience claim (aud) identifies the recipients that the JWT is intended for.
        /// </summary>
        public required string Audience { get; set; }
        /// <summary>
        /// The secret key used to sign and validate JWTs. This should be a strong, randomly generated value.
        /// </summary>
        public required string SigningKey { get; set; }
        /// <summary>
        /// The lifetime of access tokens. Default is 15 minutes.
        /// </summary>
        public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);
        /// <summary>
        /// The lifetime of refresh tokens. Default is 7 days.
        /// </summary>
        public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(7);
        /// <summary>
        /// The lifetime of email verification tokens. Default is 1 day.
        /// </summary>
        public TimeSpan EmailVerificationTokenLifetime { get; set; } = TimeSpan.FromDays(1);
        /// <summary>
        /// The lifetime of password reset tokens. Default is 30 minutes.
        /// </summary>
        public TimeSpan PasswordResetTokenLifetime { get; set; } = TimeSpan.FromMinutes(30);
    }

    /// <summary>
    /// Password validation and complexity requirements.
    /// </summary>
    public sealed class PasswordOptions
    {
        /// <summary>
        /// Minimum required password length. Default is 6.
        /// </summary>
        public int RequireMinLength { get; set; } = 6;
        /// <summary>
        /// Maximum allowed password length. Default is 100.
        /// </summary>
        public int RequireMaxLength { get; set; } = 100;
        /// <summary>
        /// Minimum number of digits required in the password. Default is 0 (no requirement).
        /// </summary>
        public int RequireDigitCount { get; set; } = 0;
        /// <summary>
        /// Minimum number of lowercase characters required in the password. Default is 0 (no requirement).
        /// </summary>
        public int RequireLowercaseCount { get; set; } = 0;
        /// <summary>
        /// Minimum number of uppercase characters required in the password. Default is 0 (no requirement).
        /// </summary>
        public int RequireUppercaseCount { get; set; } = 0;
        /// <summary>
        /// Minimum number of non-alphanumeric (special) characters required in the password. Default is 0 (no requirement).
        /// </summary>
        public int RequireNonAlphanumericCount { get; set; } = 0;
        /// <summary>
        /// Optional custom regex pattern for password validation. Default is null (no custom validation).
        /// </summary>
        public Regex? RequireRegexValidation { get; set; } = null;
        /// <summary>
        /// Optional array of allowed special characters. If null, all special characters are allowed.
        /// </summary>
        public char[]? AllowedSpecialSymbols { get; set; } = null;
    }

    /// <summary>
    /// Configuration for automatic cleanup of expired tokens.
    /// </summary>
    public sealed class TokenCleanupOptions
    {
        /// <summary>
        /// Indicates whether automatic token cleanup is enabled. Default is true.
        /// </summary>
        public bool Enabled { get; set; } = true;
        /// <summary>
        /// The interval at which the cleanup process runs. Default is 24 hours.
        /// </summary>
        public TimeSpan CleanupInterval { get; set; } = TimeSpan.FromHours(24);
        /// <summary>
        /// The period for which expired tokens are retained before being deleted. Default is 30 days.
        /// </summary>
        public TimeSpan RetentionPeriod { get; set; } = TimeSpan.FromDays(30);
    }

    public sealed class TwoFactorAuthOptions
    {
        public required string Issuer { get; set; }
        public TimeSpan SetupTokenLifetime { get; set; } = TimeSpan.FromMinutes(5);
        public TimeSpan TwoFactorTokenLifetime { get; set; } = TimeSpan.FromMinutes(5);
    }
}
