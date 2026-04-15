using AuthLib.Contexts;
using AuthLib.Models;
using Microsoft.EntityFrameworkCore;


namespace AuthLib.Services.Stores
{
    public class RoleStore<TKey, TUser, TRole>(AuthDbContext<TKey, TUser, TRole> authDbContext) : BaseStore<TKey, TUser, TRole>(authDbContext)
        where TKey : IEquatable<TKey>
        where TUser : AuthUser<TKey, TRole>
        where TRole : AuthRole<TKey>
    {
        private DbSet<TRole> Roles => Context.AuthRoles;

        public void Add(TRole role)
        {
            var entry = Roles.Add(role);
        }

        public async Task<TRole> GetByNameAsync(string roleName, CancellationToken ct)
        {
            var role = await Roles.FirstOrDefaultAsync(r => r.Name.ToLower() == roleName.ToLower(), ct).ConfigureAwait(false);
            return role ?? throw new InvalidOperationException($"Role with name '{roleName}' not found.");
        }
        public async Task<TRole> GetDefaultAsync(CancellationToken ct)
        {
            var defaultRole = await Roles.Where(r => r.IsDefault)
                .FirstOrDefaultAsync(ct)
                .ConfigureAwait(false);

            return defaultRole ?? throw new InvalidOperationException("No default role found.");
        }

        public async Task<List<TRole>> GetAllAsync(CancellationToken ct)
        {
            var roles = await Roles.ToListAsync(ct)
                .ConfigureAwait(false);
            return roles;
        }

        public async Task<List<string>> GetUserRoleNamesAsync(TKey userId, CancellationToken ct)
        {
            var roleNames = await (from ur in Context.UserAuthRoles
                                   join r in Roles on ur.RoleId equals r.Id
                                   where ur.UserId.Equals(userId)
                                   select r.Name).ToListAsync(ct).ConfigureAwait(false);
            return roleNames;
        }


    }
}
