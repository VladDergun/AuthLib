using AuthLib.Enums;
using AuthLib.Models;
using AuthLib.Services;
using AuthLib.Services.Stores;
using AuthLib.Tests.Helpers;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;

namespace AuthLib.Tests.Integration
{
    [CollectionDefinition("Database collection")]
    public class DatabaseCollection : ICollectionFixture<PostgreSqlContainerFixture>
    {
    }

    /// <summary>
    /// Integration tests that verify complete authentication flows end-to-end
    /// </summary>
    [Collection("Database collection")]
    public class AuthFlowIntegrationTests : IAsyncLifetime
    {
        private readonly PostgreSqlContainerFixture _fixture;
        private TestDbContext _dbContext = null!;
        private AuthService<int, TestUser, AuthRole<int>> _authService = null!;

        public AuthFlowIntegrationTests(PostgreSqlContainerFixture fixture)
        {
            _fixture = fixture;
        }

        public async Task InitializeAsync()
        {
            _dbContext = TestDbContextFactory.CreateContext(_fixture.ConnectionString);
            
            // Ensure database exists
            await _dbContext.Database.EnsureCreatedAsync();
            
            // Clean all tables with TRUNCATE to properly reset sequences and indexes
            try
            {
                await _dbContext.Database.ExecuteSqlRawAsync("TRUNCATE TABLE \"AuthTokens\", \"AuthUserRoles\", \"AuthUserAuthProviders\", \"AuthUsers\", \"AuthRoles\" RESTART IDENTITY CASCADE");
            }
            catch
            {
                // Tables don't exist yet, recreate database
                await _dbContext.Database.EnsureDeletedAsync();
                await _dbContext.Database.EnsureCreatedAsync();
            }
            
            // Clear change tracker
            _dbContext.ChangeTracker.Clear();
            
            var authOptions = TestAuthOptionsFactory.Create();

            var authSecurityService = new AuthSecurityService(authOptions);
            var tokenManagerService = new TokenManagerService(authOptions, authSecurityService);
            var roleStore = new RoleStore<int, TestUser, AuthRole<int>>(_dbContext);
            var roleManager = new RoleSeederService<int, TestUser, AuthRole<int>>(roleStore);
            var tokenStore = new TokenStore<int, TestUser, AuthRole<int>>(_dbContext, options: authOptions);
            var userStore = new UserStore<int, TestUser, AuthRole<int>>(_dbContext);
            roleManager.SeedRolesAsync(authOptions.Value.Roles, CancellationToken.None)
                .GetAwaiter().GetResult();
            
            // Clear change tracker after role seeding to ensure queries see clean state
            _dbContext.ChangeTracker.Clear();

            var authService = new AuthService<int, TestUser, AuthRole<int>>(
                authSecurityService, _dbContext, authOptions, tokenManagerService, roleStore, userStore, tokenStore);

            _authService = authService;

            await Task.CompletedTask;
        }

        public async Task DisposeAsync()
        {
            await _dbContext.Database.EnsureDeletedAsync();
            await _dbContext.DisposeAsync();
        }

        [Fact]
        public async Task CompleteUserJourney_RegisterLoginRefreshLogout_ShouldWork()
        {
            // Step 1: Register
            var email = "journey@example.com";
            var password = "Password123";
            var registerResult = await _authService.RegisterAsync(email, password, CancellationToken.None);

            registerResult.IsSuccess.Should().BeTrue();
            var initialAccessToken = registerResult.Value!.AccessToken;
            var initialRefreshToken = registerResult.Value.Token;

            // Step 2: Login
            var loginResult = await _authService.LoginAsync(email, password, CancellationToken.None);

            loginResult.IsSuccess.Should().BeTrue();
            loginResult.Value!.AccessToken.Should().NotBe(initialAccessToken);
            var loginRefreshToken = loginResult.Value.Token;

            // Step 3: Refresh token
            var refreshResult = await _authService.RefreshAsync(loginRefreshToken, CancellationToken.None);

            refreshResult.IsSuccess.Should().BeTrue();
            refreshResult.Value!.Token.Should().NotBe(loginRefreshToken);

            // Step 4: Logout
            var logoutResult = await _authService.LogoutAsync(refreshResult.Value.Token, CancellationToken.None);

            logoutResult.IsSuccess.Should().BeTrue();

            // Step 5: Try to use logged out token
            var failedRefresh = await _authService.RefreshAsync(refreshResult.Value.Token, CancellationToken.None);

            failedRefresh.IsSuccess.Should().BeFalse();
        }

        [Fact]
        public async Task PasswordResetFlow_ShouldWorkEndToEnd()
        {
            // Step 1: Register user
            var email = "resetflow@example.com";
            var oldPassword = "OldPassword123";
            var newPassword = "NewPassword456";

            await _authService.RegisterAsync(email, oldPassword, CancellationToken.None);

            // Step 2: Login to create session
            var loginResult = await _authService.LoginAsync(email, oldPassword, CancellationToken.None);
            loginResult.IsSuccess.Should().BeTrue();
            var sessionToken = loginResult.Value!.Token;

            // Step 3: Request password reset
            var resetRequest = await _authService.RequestPasswordResetAsync(email, CancellationToken.None);
            resetRequest.IsSuccess.Should().BeTrue();
            var resetToken = resetRequest.Value!;

            // Step 4: Reset password
            var resetResult = await _authService.ResetPasswordAsync(resetToken, newPassword, CancellationToken.None);
            resetResult.IsSuccess.Should().BeTrue();

            // Step 5: Old session should be invalidated
            var oldSessionRefresh = await _authService.RefreshAsync(sessionToken, CancellationToken.None);
            oldSessionRefresh.IsSuccess.Should().BeFalse();

            // Step 6: Login with new password should work
            var newLogin = await _authService.LoginAsync(email, newPassword, CancellationToken.None);
            newLogin.IsSuccess.Should().BeTrue();

            // Step 7: Login with old password should fail
            var oldLogin = await _authService.LoginAsync(email, oldPassword, CancellationToken.None);
            oldLogin.IsSuccess.Should().BeFalse();
        }

        [Fact]
        public async Task MultiDeviceScenario_ShouldHandleMultipleSessions()
        {
            // Setup: Register user
            var email = "multidevice@example.com";
            var password = "Password123";
            await _authService.RegisterAsync(email, password, CancellationToken.None);

            // Device 1: Login
            var device1Login = await _authService.LoginAsync(email, password, CancellationToken.None);
            var device1Token = device1Login.Value!.Token;

            // Device 2: Login
            var device2Login = await _authService.LoginAsync(email, password, CancellationToken.None);
            var device2Token = device2Login.Value!.Token;

            // Device 3: Login
            var device3Login = await _authService.LoginAsync(email, password, CancellationToken.None);
            var device3Token = device3Login.Value!.Token;

            // All devices should have valid tokens
            var user = await _dbContext.AuthUsers.FirstAsync(u => u.Email == email);
            var activeTokens = await _dbContext.AuthTokens
                .Where(t => t.UserId == user.Id && !t.IsRevoked)
                .CountAsync();
            activeTokens.Should().BeGreaterThanOrEqualTo(3);

            // Logout from all devices
            await _authService.LogoutAllAsync(device1Token, CancellationToken.None);

            // All tokens should be revoked
            var revokedTokens = await _dbContext.AuthTokens
                .Where(t => t.UserId == user.Id)
                .ToListAsync();
            revokedTokens.Should().AllSatisfy(t => t.IsRevoked.Should().BeTrue());

            // None of the devices should be able to refresh
            (await _authService.RefreshAsync(device1Token, CancellationToken.None)).IsSuccess.Should().BeFalse();
            (await _authService.RefreshAsync(device2Token, CancellationToken.None)).IsSuccess.Should().BeFalse();
            (await _authService.RefreshAsync(device3Token, CancellationToken.None)).IsSuccess.Should().BeFalse();
        }

        [Fact]
        public async Task TokenReuseDetection_ShouldRevokeAllTokens()
        {
            // Setup
            var email = "tokenreuse@example.com";
            var password = "Password123";
            await _authService.RegisterAsync(email, password, CancellationToken.None);

            var login = await _authService.LoginAsync(email, password, CancellationToken.None);
            var token1 = login.Value!.Token;

            // Refresh to get new token
            var refresh1 = await _authService.RefreshAsync(token1, CancellationToken.None);
            var token2 = refresh1.Value!.Token;

            // Try to reuse old token (security breach simulation)
            var reuseAttempt = await _authService.RefreshAsync(token1, CancellationToken.None);

            // Should fail and revoke all tokens
            reuseAttempt.IsSuccess.Should().BeFalse();

            // New token should also be revoked
            var token2Attempt = await _authService.RefreshAsync(token2, CancellationToken.None);
            token2Attempt.IsSuccess.Should().BeFalse();

            // User must login again
            var newLogin = await _authService.LoginAsync(email, password, CancellationToken.None);
            newLogin.IsSuccess.Should().BeTrue();
        }

        [Fact]
        public async Task AdminRevokeTokens_ShouldForceRelogin()
        {
            // Setup: User with active session
            var email = "adminrevoke@example.com";
            var password = "Password123";
            var result = await _authService.RegisterAsync(email, password, CancellationToken.None);
            result.IsSuccess.Should().BeTrue();

            var login = await _authService.LoginAsync(email, password, CancellationToken.None);
            login.IsSuccess.Should().BeTrue();
            var userToken = login.Value!.Token;

            // Admin action: Revoke all user tokens
            var user = await _dbContext.AuthUsers.FirstAsync(u => u.Email == email);

            var tokenStore = new TokenStore<int, TestUser, AuthRole<int>>(_dbContext, options: TestAuthOptionsFactory.Create());

            await tokenStore.RevokeUserTokens(user.Id, [TokenRevokationOption.All], CancellationToken.None);
            await _dbContext.SaveChangesAsync();

            // User's token should no longer work
            var refreshAttempt = await _authService.RefreshAsync(userToken, CancellationToken.None);
            refreshAttempt.IsSuccess.Should().BeFalse();

            // User can still login
            var newLogin = await _authService.LoginAsync(email, password, CancellationToken.None);
            newLogin.IsSuccess.Should().BeTrue();
        }

        [Fact]
        public async Task ConcurrentRegistrations_ShouldHandleRaceCondition()
        {
            // Attempt to register the same email concurrently
            var email = "concurrent@example.com";
            var password = "Password123";

            // Shared options (read-only, thread-safe)
            var authOptions = TestAuthOptionsFactory.Create();

            // Seed roles once using a temporary context
            using (var tempContext = TestDbContextFactory.CreateContext(_fixture.ConnectionString))
            {
                var tempRoleStore = new RoleStore<int, TestUser, AuthRole<int>>(tempContext);
                var roleManager = new RoleSeederService<int, TestUser, AuthRole<int>>(tempRoleStore);
                await roleManager.SeedRolesAsync(authOptions.Value.Roles, CancellationToken.None);
            }

            // Create separate DbContext and service instances for each concurrent operation
            // DbContext is not thread-safe, so each concurrent operation needs its own instance
            var tasks = Enumerable.Range(0, 5)
                .Select(_ =>
                {
                    var dbContext = TestDbContextFactory.CreateContext(_fixture.ConnectionString);
                    var authSecurityService = new AuthSecurityService(authOptions);
                    var tokenManagerService = new TokenManagerService(authOptions, authSecurityService);
                    var roleStore = new RoleStore<int, TestUser, AuthRole<int>>(dbContext);
                    var userStore = new UserStore<int, TestUser, AuthRole<int>>(dbContext);
                    var tokenStore = new TokenStore<int, TestUser, AuthRole<int>>(dbContext, options: authOptions);
                    var authService = new AuthService<int, TestUser, AuthRole<int>>(
                        authSecurityService, dbContext, authOptions, tokenManagerService, roleStore, userStore, tokenStore);

                    return authService.RegisterAsync(email, password, CancellationToken.None);
                })
                .ToArray();

            var results = await Task.WhenAll(tasks);

            // Only one should succeed
            results.Count(r => r.IsSuccess).Should().Be(1);
            results.Count(r => !r.IsSuccess).Should().Be(4);

            // Only one user should exist in database
            var users = await _dbContext.AuthUsers.Where(u => u.Email == email).ToListAsync();
            users.Should().HaveCount(1);
        }

    }
}
