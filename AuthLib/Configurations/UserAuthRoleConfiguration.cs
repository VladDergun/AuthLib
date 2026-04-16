using AuthLib.Models.Join;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;


namespace AuthLib.Configurations
{
    internal class UserAuthRoleConfiguration<TKey> : IEntityTypeConfiguration<UserAuthRole<TKey>>
        where TKey : IEquatable<TKey>
    {
        private readonly string? _schema;

        public UserAuthRoleConfiguration(string? schema)
        {
            _schema = schema;
        }

        public void Configure(EntityTypeBuilder<UserAuthRole<TKey>> builder)
        {
            builder.HasKey(x => new { x.UserId, x.RoleId });

            if (!string.IsNullOrWhiteSpace(_schema))
            {
                builder.ToTable("UserAuthRoles", _schema);
            }
            else
            {
                builder.ToTable("UserAuthRoles");
            }
        }
    }
}
