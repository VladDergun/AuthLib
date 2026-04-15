using AuthLib.Interfaces.Services;
using AuthLib.Options;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace AuthLib.Services.Hosted
{
    /// <summary>
    /// Task that runs on application startup to seed default roles into the database based on the configured AuthOptions.
    /// </summary>
    /// <param name="serviceProvider">The service provider used to resolve dependencies.</param>
    /// <param name="authOptions">The authentication options containing role configuration.</param>
    internal class RoleSeedingTask(IServiceProvider serviceProvider, IOptions<AuthOptions> authOptions) : IHostedService
    {
        private readonly IServiceProvider _serviceProvider = serviceProvider;
        private readonly AuthOptions _authOptions = authOptions.Value;

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            await using var scope = _serviceProvider.CreateAsyncScope();

            IRoleSeederService seederService = scope.ServiceProvider.GetRequiredService<IRoleSeederService>();

            await seederService.SeedRolesAsync(_authOptions.Roles, cancellationToken);
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }
}
