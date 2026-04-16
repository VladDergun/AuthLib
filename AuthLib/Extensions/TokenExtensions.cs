using AuthLib.Models;

namespace AuthLib.Extensions
{
    internal static class TokenExtensions
    {
        public static void Revoke<TKey>(this AuthToken<TKey> token)
            where TKey : IEquatable<TKey>
        {
            token.IsRevoked = true;
            token.RevokedAt = DateTime.UtcNow;
        }
    }
}
