using AuthLib.Configurations;
using AuthLib.Interfaces;
using AuthLib.Models;
using AuthLib.Models.Join;
using Microsoft.EntityFrameworkCore;

namespace AuthLib.Contexts
{
    public abstract class AuthDbContext<TUser> : AuthDbContext<string, TUser, AuthRole<string>>
        where TUser : AuthUser<string, AuthRole<string>>
    {
        /// <summary>
        /// Creates a new instance of the AuthDbContext class.
        /// </summary>
        /// <param name="options">DbContext options.</param>
        /// <param name="schema">Schema used for the authentication tables. If null, no schema will be used.</param>
        public AuthDbContext(DbContextOptions options, string? schema = null) : base(options, schema) { }
    }

    public abstract class AuthDbContext<TKey, TUser> : AuthDbContext<TKey, TUser, AuthRole<TKey>>
        where TUser : AuthUser<TKey, AuthRole<TKey>>
        where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// Creates a new instance of the AuthDbContext class.
        /// </summary>
        /// <param name="options">DbContext options.</param>
        /// <param name="schema">Schema used for the authentication tables. If null, no schema will be used.</param>
        public AuthDbContext(DbContextOptions options, string? schema = null) : base(options, schema) { }
    }

    public abstract class AuthDbContext<TKey, TUser, TRole>
        : DbContext, IAuthDbContext
        where TKey : IEquatable<TKey>
        where TUser : AuthUser<TKey, TRole>
        where TRole : AuthRole<TKey>
    {
        protected string? Schema { get; }

        /// <summary>
        /// Creates a new instance of the AuthDbContext class.
        /// </summary>
        /// <param name="options">DbContext options.</param>
        /// <param name="schema">Schema used for the authentication tables. If null, no schema will be used.</param>
        public AuthDbContext(DbContextOptions options, string? schema = null) : base(options)
        {
            Schema = schema;
        }

        public DbSet<TUser> AuthUsers => Set<TUser>();
        public DbSet<TRole> AuthRoles => Set<TRole>();
        public DbSet<AuthToken<TKey>> AuthTokens => Set<AuthToken<TKey>>();
        public DbSet<UserAuthProvider<TKey>> UserAuthProviders => Set<UserAuthProvider<TKey>>();
        public DbSet<UserAuthRole<TKey>> UserAuthRoles => Set<UserAuthRole<TKey>>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.ApplyConfiguration(new AuthUserConfiguration<TKey, TUser, TRole>());
            modelBuilder.ApplyConfiguration(new UserAuthRoleConfiguration<TKey>(Schema));
            modelBuilder.ApplyConfiguration(new AuthProviderConfiguration<TKey>(Schema));
            modelBuilder.ApplyConfiguration(new AuthTokenConfiguration<TKey>(Schema));
            modelBuilder.ApplyConfiguration(new AuthRoleConfiguration<TKey>(Schema));
        }

        public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            UpdateConcurrencyStamps();
            return base.SaveChangesAsync(cancellationToken);
        }

        public override int SaveChanges()
        {
            UpdateConcurrencyStamps();
            return base.SaveChanges();
        }


        private void UpdateConcurrencyStamps()
        {
            var modifiedEntries = ChangeTracker.Entries()
                .Where(e => e.State == EntityState.Modified);

            foreach (var entry in modifiedEntries)
            {
                if (entry.Entity is TUser user)
                {
                    user.ConcurrencyStamp = Guid.NewGuid().ToString();
                }
                else if (entry.Entity is TRole role)
                {
                    role.ConcurrencyStamp = Guid.NewGuid().ToString();
                }
                else if (entry.Entity is AuthToken<TKey> token)
                {
                    token.ConcurrencyStamp = Guid.NewGuid().ToString();
                }
            }
        }

    }
}

