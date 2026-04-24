using AuthLib.Contexts;
using AuthLib.Interfaces.Services;
using AuthLib.Models;
using Microsoft.EntityFrameworkCore;


namespace AuthLib.Services.Stores
{
    public class RoleStore<TKey, TUser, TRole>(AuthDbContext<TKey, TUser, TRole> authDbContext) : BaseStore<TKey, TUser, TRole>(authDbContext), IRoleStore<TRole>
        where TKey : IEquatable<TKey>
        where TUser : AuthUser<TKey, TRole>
        where TRole : AuthRole<TKey>
    {
        public DbSet<TRole> Roles => Context.AuthRoles;

        public async Task<TRole?> GetByNameAsync(string roleName, CancellationToken ct = default!)
        {
            var role = await Roles.FirstOrDefaultAsync(r => r.Name.ToLower() == roleName.ToLower(), ct)
                .ConfigureAwait(false);
            return role;
        }

        public async Task<TRole> GetDefaultAsync(CancellationToken ct = default!)
        {
            var defaultRole = await Roles.Where(r => r.IsDefault)
                .FirstOrDefaultAsync(ct)
                .ConfigureAwait(false);

            return defaultRole ?? throw new InvalidOperationException("Default role was not found");
        }

        public async Task<IReadOnlyCollection<TRole>> GetAllAsync(CancellationToken ct = default!)
        {
            var roles = await Roles.ToListAsync(ct)
                .ConfigureAwait(false);
            return roles;
        }

        public async Task<IReadOnlyCollection<string>> GetUserRoleNamesAsync(string userId, CancellationToken ct = default!)
        {
            var roleNames = await (from ur in Context.UserAuthRoles
                                   join r in Roles on ur.RoleId equals r.Id
                                   where ur.UserId.Equals(userId)
                                   select r.Name).ToListAsync(ct).ConfigureAwait(false);
            return roleNames;
        }

        internal void Add(TRole role)
        {
            Roles.Add(role);
        }

        internal async Task<List<string>> GetUserRoleNamesAsync(TKey userId, CancellationToken ct = default!)
        {
            var roleNames = await (from ur in Context.UserAuthRoles
                                   join r in Roles on ur.RoleId equals r.Id
                                   where ur.UserId.Equals(userId)
                                   select r.Name).ToListAsync(ct).ConfigureAwait(false);
            return roleNames;
        }
    }
}
