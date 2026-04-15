using AuthLib.Contexts;
using AuthLib.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AuthLib.Services.Hosted
{
    /// <summary>
    /// Task that runs in the background to periodically clean up expired and revoked tokens from the database.
    /// </summary>
    /// <typeparam name="TKey"></typeparam>
    /// <typeparam name="TUser"></typeparam>
    /// <typeparam name="TRole"></typeparam>
    internal class TokenCleanupTask<TKey, TUser, TRole> : BackgroundService
        where TKey : IEquatable<TKey>
        where TUser : AuthUser<TKey, TRole>
        where TRole : AuthRole<TKey>
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<TokenCleanupTask<TKey, TUser, TRole>> _logger;
        private readonly TimeSpan _cleanupInterval;
        private readonly TimeSpan _retentionPeriod;

        public TokenCleanupTask(
            IServiceProvider serviceProvider,
            ILogger<TokenCleanupTask<TKey, TUser, TRole>> logger,
            TimeSpan? cleanupInterval = null,
            TimeSpan? retentionPeriod = null)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
            _cleanupInterval = cleanupInterval ?? TimeSpan.FromHours(24);
            _retentionPeriod = retentionPeriod ?? TimeSpan.FromDays(30);
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Token Cleanup Service started. Cleanup interval: {Interval}, Retention period: {Retention}",
                _cleanupInterval, _retentionPeriod);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(_cleanupInterval, stoppingToken);

                    if (stoppingToken.IsCancellationRequested)
                        break;

                    await CleanupExpiredTokensAsync(stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    _logger.LogInformation("Token Cleanup Service is stopping.");
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error occurred during token cleanup.");
                }
            }
        }

        private async Task CleanupExpiredTokensAsync(CancellationToken cancellationToken)
        {
            await using var scope = _serviceProvider.CreateAsyncScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext<TKey, TUser, TRole>>();

            var cutoffDate = DateTime.UtcNow.Subtract(_retentionPeriod);

            var deletedCount = await dbContext.AuthTokens
                .Where(t =>
                    (t.IsRevoked && t.RevokedAt.HasValue && t.RevokedAt.Value < cutoffDate) ||
                    (!t.IsRevoked && t.TokenExpiry < cutoffDate))
                .ExecuteDeleteAsync(cancellationToken);

            if (deletedCount > 0)
            {
                _logger.LogInformation("Token cleanup completed. Deleted {Count} expired/revoked tokens older than {CutoffDate}",
                    deletedCount, cutoffDate);
            }
            else
            {
                _logger.LogDebug("Token cleanup completed. No tokens to delete.");
            }
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Token Cleanup Service is stopping.");
            await base.StopAsync(cancellationToken);
        }
    }
}
