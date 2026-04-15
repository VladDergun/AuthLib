using AuthLib.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;


namespace AuthLib.Configurations
{
    internal class AuthTokenConfiguration<TKey> : IEntityTypeConfiguration<AuthToken<TKey>>
        where TKey : IEquatable<TKey>
    {
        private readonly string? _schema;

        public AuthTokenConfiguration(string? schema)
        {
            _schema = schema;
        }

        public void Configure(EntityTypeBuilder<AuthToken<TKey>> builder)
        {
            if (!string.IsNullOrWhiteSpace(_schema))
            {
                builder.ToTable("AuthTokens", _schema);
            }

            builder.HasIndex(x => x.TokenHash).IsUnique();
            builder.HasIndex(x => new { x.UserId, x.IsRevoked });
            builder.HasIndex(x => x.UserId);
            builder.HasIndex(x => x.TokenExpiry);
            builder.HasIndex(x => x.TokenType);
            builder.HasIndex(x => new { x.TokenType, x.IsRevoked });

            builder.Property(t => t.ConcurrencyStamp)
                .IsConcurrencyToken()
                .HasMaxLength(36);
        }
    }
}
