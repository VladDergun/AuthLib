using AuthLib.Contexts;
using AuthLib.Enums;
using AuthLib.Models;
using AuthLib.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Collections.Immutable;


namespace AuthLib.Services.Stores
{
    internal class TokenStore<TKey, TUser, TRole>(
        AuthDbContext<TKey, TUser, TRole> authDbContext,
        IOptions<AuthOptions> options) : BaseStore<TKey, TUser, TRole>(authDbContext)
        where TKey : IEquatable<TKey>
        where TUser : AuthUser<TKey, TRole>
        where TRole : AuthRole<TKey>
    {
        private readonly AuthOptions _options = options.Value;
        private DbSet<AuthToken<TKey>> Tokens => Context.AuthTokens;


        public async Task<AuthToken<TKey>?> GetTokenAsync(string tokenHash, CancellationToken ct = default)
        {
            return await Tokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash, ct)
                .ConfigureAwait(false);
        }

        public void AddRefreshToken(TKey userId, string tokenHash)
        {
            Tokens.Add(new AuthToken<TKey>
            {
                UserId = userId,
                TokenHash = tokenHash,
                IsRevoked = false,
                TokenType = TokenType.Refresh,
                TokenExpiry = DateTime.UtcNow.Add(_options.JWTOptions.RefreshTokenLifetime)
            });
        }

        public void AddEmailVerificationToken(TKey userId, string tokenHash)
        {
            Tokens.Add(new AuthToken<TKey>
            {
                UserId = userId,
                TokenHash = tokenHash,
                IsRevoked = false,
                TokenType = TokenType.EmailVerification,
                TokenExpiry = DateTime.UtcNow.Add(_options.JWTOptions.EmailVerificationTokenLifetime)
            });
        }

        public void AddPasswordResetToken(TKey userId, string tokenHash)
        {
            Tokens.Add(new AuthToken<TKey>
            {
                UserId = userId,
                TokenHash = tokenHash,
                IsRevoked = false,
                TokenType = TokenType.PasswordReset,
                TokenExpiry = DateTime.UtcNow.Add(_options.JWTOptions.PasswordResetTokenLifetime)
            });
        }

        public void AddTwoFactorAuthToken(TKey userId, string tokenHash)
        {
            Tokens.Add(new AuthToken<TKey>
            {
                UserId = userId,
                TokenHash = tokenHash,
                IsRevoked = false,
                TokenType = TokenType.TwoFactorAuth,
                TokenExpiry = DateTime.UtcNow.Add(_options.TwoFactorAuthOptions!.TwoFactorTokenLifetime)
            });
        }

        public async Task RevokeUserTokens(TKey userId, ImmutableHashSet<TokenRevokationOption> tokenRevocationOptions, CancellationToken ct = default)
        {
            var query = Tokens
                .Where(t => t.UserId.Equals(userId) && !t.IsRevoked);

            if (!tokenRevocationOptions.Contains(TokenRevokationOption.All))
            {
                var typesToRevoke = new List<TokenType>();

                if (tokenRevocationOptions.Contains(TokenRevokationOption.Refresh))
                    typesToRevoke.Add(TokenType.Refresh);

                if (tokenRevocationOptions.Contains(TokenRevokationOption.PasswordReset))
                    typesToRevoke.Add(TokenType.PasswordReset);

                if (tokenRevocationOptions.Contains(TokenRevokationOption.EmailVerification))
                    typesToRevoke.Add(TokenType.EmailVerification);

                if (tokenRevocationOptions.Contains(TokenRevokationOption.TwoFactorAuth))
                    typesToRevoke.Add(TokenType.TwoFactorAuth);

                if (typesToRevoke.Count > 0)
                {
                    query = query.Where(t => typesToRevoke.Contains(t.TokenType));
                }
            }

            var tokens = await query.ToListAsync(ct)
                .ConfigureAwait(false);

            foreach (var token in tokens)
            {
                token.IsRevoked = true;
                token.RevokedAt = DateTime.UtcNow;
            }
        }

    }
}
