using AuthLib.Models;
using System;
using System.Collections.Generic;
using System.Text;

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
