using AuthLib.Models.Join;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthLib.Models
{
    /// <summary>
    /// Creates a new instance of the AuthRole class with default key type as string.
    /// </summary>
    public class AuthRole : AuthRole<string>
    {
    }

    /// <summary>
    /// Creates a new instance of the AuthRole class with specified key type.
    /// </summary>
    /// <typeparam name="TRoleKey">AuthRole key type</typeparam>
    [Table(name: "AuthRoles")]
    public class AuthRole<TRoleKey> where TRoleKey : IEquatable<TRoleKey>
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public TRoleKey Id { get; set; } = default!;
        public string Name { get; set; } = string.Empty;
        public bool IsDefault { get; set; } = false;
        public bool IsActive { get; set; } = true;
        [ConcurrencyCheck]
        public string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();
        public List<UserAuthRole<TRoleKey>> UserAuthRoles { get; set; } = [];
    }
}
