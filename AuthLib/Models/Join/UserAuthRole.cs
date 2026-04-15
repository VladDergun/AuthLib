using System.ComponentModel.DataAnnotations.Schema;

namespace AuthLib.Models.Join
{
    [Table(name: "UserAuthRoles")]
    public class UserAuthRole<TKey>
        where TKey : IEquatable<TKey>
    {
        public TKey UserId { get; set; } = default!;
        public TKey RoleId { get; set; } = default!;
    }
}
