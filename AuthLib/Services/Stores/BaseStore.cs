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
        public readonly AuthDbContext<TKey, TUser, TRole> Context = authDbContext;
    }
}
