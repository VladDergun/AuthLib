using AuthLib.Enums;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthLib.Models
{
    [Table(name: "UserAuthProviders")]
    public sealed class UserAuthProvider<TKey>
        where TKey : IEquatable<TKey>
    {
        [Key]
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public TKey UserId { get; set; } = default!;
        public ExternalAuthProvider Provider { get; set; }
        public string ProviderUserId { get; set; } = string.Empty;
    }
}
