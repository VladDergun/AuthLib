using AuthLib.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthLib.Configurations
{
    internal class AuthProviderConfiguration<TKey> : IEntityTypeConfiguration<UserAuthProvider<TKey>>
        where TKey : IEquatable<TKey>
    {
        private readonly string? _schema;

        public AuthProviderConfiguration(string? schema)
        {
            _schema = schema;
        }

        public void Configure(EntityTypeBuilder<UserAuthProvider<TKey>> builder)
        {
            if (!string.IsNullOrWhiteSpace(_schema))
            {
                builder.ToTable("UserAuthProviders", _schema);
            }

            builder.HasIndex(x => new { x.Provider, x.ProviderUserId }).IsUnique();
            builder.HasIndex(x => x.UserId);
        }
    }
}
