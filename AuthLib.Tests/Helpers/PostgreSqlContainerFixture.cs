using Testcontainers.PostgreSql;

namespace AuthLib.Tests.Helpers
{
    public class PostgreSqlContainerFixture : IAsyncLifetime
    {
        private readonly PostgreSqlContainer _container;

        public PostgreSqlContainerFixture()
        {
            _container = new PostgreSqlBuilder("postgres:17-alpine")
                .WithDatabase("authlib_test")
                .WithUsername("postgres")
                .WithPassword("postgres")
                .Build();
        }

        public string ConnectionString => _container.GetConnectionString();

        public async Task InitializeAsync()
        {
            await _container.StartAsync();
        }

        public async Task DisposeAsync()
        {
            await _container.DisposeAsync();
        }
    }
}
