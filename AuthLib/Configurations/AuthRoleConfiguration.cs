using AuthLib.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthLib.Configurations
{
    internal class AuthRoleConfiguration<TRoleKey> : IEntityTypeConfiguration<AuthRole<TRoleKey>>
        where TRoleKey : IEquatable<TRoleKey>
    {
        private readonly string? _schema;

        public AuthRoleConfiguration(string? schema)
        {
            _schema = schema;
        }

        public void Configure(EntityTypeBuilder<AuthRole<TRoleKey>> builder)
        {
            if (!string.IsNullOrWhiteSpace(_schema))
            {
                builder.ToTable("AuthRoles", _schema);
            }


            builder.HasIndex(x => x.Name).IsUnique();

            builder.Property(r => r.ConcurrencyStamp)
                .IsConcurrencyToken()
                .HasMaxLength(36);

            builder.HasMany(r => r.UserAuthRoles)
                .WithOne()
                .HasForeignKey(ur => ur.RoleId);
        }
    }
}
