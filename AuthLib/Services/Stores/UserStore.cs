using AuthLib.Common.AuthResults;
using AuthLib.Contexts;
using AuthLib.Interfaces.Services;
using AuthLib.Models;
using AuthLib.Services.IdGenerators;
using Microsoft.EntityFrameworkCore;

namespace AuthLib.Services.Stores
{
    public class UserStore<TKey, TUser, TRole>(AuthDbContext<TKey, TUser, TRole> authDbContext) : BaseStore<TKey, TUser, TRole>(authDbContext), IUserStore<TUser>
        where TKey : IEquatable<TKey>
        where TUser : AuthUser<TKey, TRole>
        where TRole : AuthRole<TKey>
    {
        public DbSet<TUser> Users => Context.AuthUsers;

        public async Task<TUser?> GetByIdAsync(TKey id, CancellationToken ct)
        {
            return await Users.FirstOrDefaultAsync(u => u.Id.Equals(id), ct)
                .ConfigureAwait(false);
        }

        public async Task<string?> GetUserEmailAsync(TKey id, CancellationToken ct)
        {
            return await Users
                .Where(u => u.Id.Equals(id))
                .Select(u => u.Email)
                .FirstOrDefaultAsync(ct)
                .ConfigureAwait(false);
        }

        public async Task<TUser?> GetByIdAsync(string id, CancellationToken ct = default)
        {
            var typedId = IdConverter<TKey>.FromString(id);
            return await GetByIdAsync(typedId, ct).ConfigureAwait(false);
        }

        public async Task<string?> GetUserEmailAsync(string id, CancellationToken ct = default)
        {
            var typedId = IdConverter<TKey>.FromString(id);
            return await GetUserEmailAsync(typedId, ct).ConfigureAwait(false);
        }
    }
}
