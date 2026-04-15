using AuthLib.Models.Join;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthLib.Models
{
    public class AuthUser : AuthUser<string, AuthRole<string>>
    {

    }
    /// <summary>
    /// Creates a new instance of the AuthUser class with set key. Role will have default type as string.
    /// </summary>
    /// <typeparam name="TKey">AuthUser and AuthRole key type</typeparam>
    public class AuthUser<TKey> : AuthUser<TKey, AuthRole<TKey>>
        where TKey : IEquatable<TKey>
    {

    }

    /// <summary>
    /// Creates a new instance of the AuthUser class with set key and role type.
    /// </summary>
    /// <typeparam name="TKey">AuthUser and AuthRole key type</typeparam>
    /// <typeparam name="TRole">AuthUser role type</typeparam>
    public class AuthUser<TKey, TRole>
        where TKey : IEquatable<TKey>
        where TRole : AuthRole<TKey>
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public TKey Id { get; set; } = default!;
        public string Email { get; set; } = string.Empty;
        public string? HashedPassword { get; set; }
        public bool IsAutoOAuthBindingEnabled { get; set; }
        public bool IsEmailVerified { get; set; }

        [ConcurrencyCheck]
        public string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();
        public virtual List<UserAuthProvider<TKey>> UserAuthProviders { get; set; } = [];
        public virtual List<UserAuthRole<TKey>> UserRoles { get; set; } = [];
        public virtual List<AuthToken<TKey>> AuthTokens { get; set; } = [];

    }
}
