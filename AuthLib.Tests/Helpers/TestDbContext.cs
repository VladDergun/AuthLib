using AuthLib.Contexts;
using AuthLib.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthLib.Tests.Helpers
{
    public class TestUser : AuthUser<int, AuthRole<int>>
    {
    }

    public class TestDbContext : AuthDbContext<int, TestUser, AuthRole<int>>
    {
        public TestDbContext(DbContextOptions<TestDbContext> options) : base(options)
        {
        }
    }
}
