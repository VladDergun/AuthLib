using AuthLib.Contexts;
using AuthLib.Models;

namespace AuthLib.Services.Stores
{
    public class BaseStore<TKey, TUser, TRole>(
        AuthDbContext<TKey, TUser, TRole> authDbContext)
        where TKey : IEquatable<TKey>
        where TUser : AuthUser<TKey, TRole>
        where TRole : AuthRole<TKey>
    {
        protected readonly AuthDbContext<TKey, TUser, TRole> Context = authDbContext;

        public async Task<int> SaveChangesAsync(CancellationToken ct = default!)
        {
            return await Context.SaveChangesAsync(ct);
        }

        public int SaveChanges()
        {
            return Context.SaveChanges();
        }
    }
}
