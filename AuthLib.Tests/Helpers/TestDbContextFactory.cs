using Microsoft.EntityFrameworkCore;

namespace AuthLib.Tests.Helpers
{
    public static class TestDbContextFactory
    {
        public static TestDbContext CreateContext(string connectionString)
        {
            var options = new DbContextOptionsBuilder<TestDbContext>()
                .UseNpgsql(connectionString)
                .Options;

            var context = new TestDbContext(options);
            context.Database.EnsureCreated();
            return context;
        }
    }
}
