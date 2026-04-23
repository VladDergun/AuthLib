using AuthLib.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthLib.Configurations
{
    internal class AuthUserConfiguration<TKey, TUser, TRole> : IEntityTypeConfiguration<TUser>
        where TKey : IEquatable<TKey>
        where TUser : AuthUser<TKey, TRole>
        where TRole : AuthRole<TKey>
    {
        private readonly bool _useOAuth;

        public AuthUserConfiguration(bool useOAuth = false)
        {
            _useOAuth = useOAuth;
        }

        public void Configure(EntityTypeBuilder<TUser> builder)
        {
            builder.HasIndex(x => x.Email).IsUnique();

            builder.HasMany(u => u.UserRoles)
                .WithOne()
                .HasForeignKey(u => u.UserId);

            builder.HasMany(u => u.AuthTokens)
                .WithOne()
                .HasForeignKey(uc => uc.UserId);

            if (_useOAuth)
            {
                builder.HasMany(u => u.UserAuthProviders)
                    .WithOne()
                    .HasForeignKey(uc => uc.UserId);
            }
            else
            {
                builder.Ignore(u => u.UserAuthProviders);
                builder.Ignore(u => u.IsTwoFactorAuthEnabled);
            }

            builder.Property(u => u.ConcurrencyStamp)
                .IsConcurrencyToken()
                .HasMaxLength(36);
        }
    }
}
