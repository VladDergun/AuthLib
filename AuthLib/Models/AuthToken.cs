using AuthLib.Enums;
using AuthLib.Models.Shared;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthLib.Models
{
    [Table(name: "AuthTokens")]
    public sealed class AuthToken<TKey> : AuditEntity
        where TKey : IEquatable<TKey>
    {
        [Key]
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public TKey UserId { get; set; } = default!;
        public string TokenHash { get; set; } = string.Empty;
        public DateTime TokenExpiry { get; set; }
        public bool IsRevoked { get; set; }
        public DateTime? RevokedAt { get; set; }

        public TokenType TokenType { get; set; } = TokenType.Refresh;

        [ConcurrencyCheck]
        public string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();
    }
}
