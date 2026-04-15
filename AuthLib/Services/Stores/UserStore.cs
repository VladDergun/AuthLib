using AuthLib.Contexts;
using AuthLib.Models;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Text;

namespace AuthLib.Services.Stores
{
    public class UserStore<TKey, TUser, TRole>(AuthDbContext<TKey, TUser, TRole> authDbContext) : BaseStore<TKey, TUser, TRole>(authDbContext)
        where TKey : IEquatable<TKey>
        where TUser : AuthUser<TKey, TRole>
        where TRole : AuthRole<TKey>
    {
        public DbSet<TUser> Users => Context.AuthUsers;

        public async Task<TUser> GetByIdAsync(TKey id, CancellationToken ct)
        {
            var user = await Users.FirstOrDefaultAsync(u => u.Id.Equals(id), ct).ConfigureAwait(false);
            return user ?? throw new InvalidOperationException($"User with ID '{id}' not found.");
        }

        public async Task<string> GetUserEmailAsync(TKey id, CancellationToken ct)
        {
            return (await Users.FirstOrDefaultAsync(u => u.Id.Equals(id), ct).ConfigureAwait(false))?.Email
                ?? throw new InvalidOperationException($"User with ID '{id}' not found.");
        }
    }
}
