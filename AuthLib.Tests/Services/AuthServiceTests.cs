using AuthLib.Common.AuthResults;
using AuthLib.Enums;
using AuthLib.Interfaces.Services;
using AuthLib.Models;
using AuthLib.Options;
using AuthLib.Services;
using AuthLib.Services.Stores;
using AuthLib.Tests.Helpers;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthLib.Tests.Services
{
    public class AuthServiceTests : IClassFixture<PostgreSqlContainerFixture>, IAsyncLifetime
    {
        private readonly PostgreSqlContainerFixture _fixture;
        private TestDbContext _dbContext = null!;
        private IAuthService _authService = null!;
        private IAuthService<TestUser> _authServiceGeneric = null!;
        private IOptions<AuthOptions> _authOptions = null!;

        public AuthServiceTests(PostgreSqlContainerFixture fixture)
        {
            _fixture = fixture;
        }

        public async Task InitializeAsync()
        {
            _dbContext = TestDbContextFactory.CreateContext(_fixture.ConnectionString);
            _authOptions = TestAuthOptionsFactory.Create();

            // Setup dependencies
            var authSecurityService = new AuthSecurityService(_authOptions);
            var tokenManagerService = new TokenManagerService(_authOptions, authSecurityService);

            // Seed roles
            var roleStore = new RoleStore<int, TestUser, AuthRole<int>>(_dbContext);
            var tokenStore = new TokenStore<int, TestUser, AuthRole<int>>(_dbContext, options: _authOptions);
            var roleManager = new RoleSeederService<int, TestUser, AuthRole<int>>(roleStore);

            await roleManager.SeedRolesAsync(_authOptions.Value.Roles, CancellationToken.None);

            // Create AuthService
            var authService = new AuthService<int, TestUser, AuthRole<int>>(
                authSecurityService,
                _dbContext,
                _authOptions,
                tokenManagerService,
                roleStore,
                new UserStore<int, TestUser, AuthRole<int>>(_dbContext),
                tokenStore);

            _authService = authService;
            _authServiceGeneric = authService;

            await Task.CompletedTask;
        }

        public async Task DisposeAsync()
        {
            await _dbContext.Database.EnsureDeletedAsync();
            await _dbContext.DisposeAsync();
        }

        #region Registration Tests

        [Fact]
        public async Task RegisterAsync_WithValidCredentials_ShouldSucceed()
        {
            // Arrange
            var email = "test@example.com";
            var password = "Password123";

            // Act
            var result = await _authService.RegisterAsync(email, password, CancellationToken.None);

            // Assert
            result.IsSuccess.Should().BeTrue();
            result.Value.Should().NotBeNull();
            result.Value!.AccessToken.Should().NotBeNullOrEmpty();
            result.Value.Token.Should().NotBeNullOrEmpty();
            result.Value.UserId.Should().NotBeNullOrEmpty();

            // Verify user in database
            var user = await _dbContext.AuthUsers
                .FirstOrDefaultAsync(u => u.Email == email);
            user.Should().NotBeNull();
            user!.IsEmailVerified.Should().BeTrue();
            user.Id.ToString().Should().Be(result.Value.UserId);
        }

        [Fact]
        public async Task RegisterAsync_WithDuplicateEmail_ShouldFail()
        {
            // Arrange
            var email = "duplicate@example.com";
            var password = "Password123";
            await _authService.RegisterAsync(email, password, CancellationToken.None);

            // Act
            var result = await _authService.RegisterAsync(email, password, CancellationToken.None);

            // Assert
            result.IsSuccess.Should().BeFalse();
            result.Errors.Should().Contain(ErrorCodes.EmailAlreadyInUse);
        }

        [Fact]
        public async Task RegisterAsync_WithInvalidEmail_ShouldFail()
        {
            // Arrange
            var email = "invalid-email";
            var password = "Password123";

            // Act
            var result = await _authService.RegisterAsync(email, password, CancellationToken.None);

            // Assert
            result.IsSuccess.Should().BeFalse();
            result.Errors.Should().NotBeEmpty();
        }

        [Fact]
        public async Task RegisterAsync_WithShortPassword_ShouldFail()
        {
            // Arrange
            var email = "test@example.com";
            var password = "12345"; // Less than 6 characters

            // Act
            var result = await _authService.RegisterAsync(email, password, CancellationToken.None);

            // Assert
            result.IsSuccess.Should().BeFalse();
            result.Errors.Should().NotBeEmpty();
        }

        [Fact]
        public async Task RegisterAsync_WithSpecificRole_ShouldAssignRole()
        {
            // Arrange
            var email = "admin@example.com";
            var password = "Password123";
            var roleName = "Admin";

            // Act
            var result = await _authService.RegisterAsync(email, password, roleName, CancellationToken.None);

            // Assert
            result.IsSuccess.Should().BeTrue();

            // Verify user has Admin role
            var user = await _dbContext.AuthUsers
                .FirstOrDefaultAsync(u => u.Email == email);

            user.Should().NotBeNull();

            var role = await _dbContext.AuthRoles
                .FirstOrDefaultAsync(r => r.Name == roleName && r.UserAuthRoles.Any(ur => ur.UserId == user.Id));

            user!.UserRoles.Should().HaveCount(1);
            role.Should().NotBeNull();
        }

        #endregion

        #region Login Tests

        [Fact]
        public async Task LoginAsync_WithValidCredentials_ShouldSucceed()
        {
            // Arrange
            var email = "login@example.com";
            var password = "Password123";
            await _authService.RegisterAsync(email, password, CancellationToken.None);

            // Act
            var result = await _authService.LoginAsync(email, password, CancellationToken.None);

            // Assert
            result.IsSuccess.Should().BeTrue();
            result.Value.Should().NotBeNull();
            result.Value!.AccessToken.Should().NotBeNullOrEmpty();
            result.Value.Token.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public async Task LoginAsync_WithInvalidPassword_ShouldFail()
        {
            // Arrange
            var email = "login2@example.com";
            var password = "Password123";
            await _authService.RegisterAsync(email, password, CancellationToken.None);

            // Act
            var result = await _authService.LoginAsync(email, "WrongPassword", CancellationToken.None);

            // Assert
            result.IsSuccess.Should().BeFalse();
            result.Errors.Should().Contain(ErrorCodes.InvalidCredentials);
        }

        [Fact]
        public async Task LoginAsync_WithNonExistentUser_ShouldFail()
        {
            // Act
            var result = await _authService.LoginAsync("nonexistent@example.com", "Password123", CancellationToken.None);

            // Assert
            result.IsSuccess.Should().BeFalse();
            result.Errors.Should().Contain(ErrorCodes.InvalidCredentials);
        }

        [Fact]
        public async Task LoginAsync_WithCaseInsensitiveEmail_ShouldSucceed()
        {
            // Arrange
            var email = "CaseSensitive@Example.COM";
            var password = "Password123";
            await _authService.RegisterAsync(email, password, CancellationToken.None);

            // Act
            var result = await _authService.LoginAsync("casesensitive@example.com", password, CancellationToken.None);

            // Assert
            result.IsSuccess.Should().BeTrue();
        }

        #endregion

        #region Token Refresh Tests

        [Fact]
        public async Task RefreshAsync_WithValidToken_ShouldSucceed()
        {
            // Arrange
            var email = "refresh@example.com";
            var password = "Password123";
            var registerResult = await _authService.RegisterAsync(email, password, CancellationToken.None);
            var refreshToken = registerResult.Value!.Token;

            // Act
            var result = await _authService.RefreshAsync(refreshToken, CancellationToken.None);

            // Assert
            result.IsSuccess.Should().BeTrue();
            result.Value.Should().NotBeNull();
            result.Value!.AccessToken.Should().NotBeNullOrEmpty();
            result.Value.Token.Should().NotBeNullOrEmpty();
            result.Value.Token.Should().NotBe(refreshToken); // Token rotation
        }

        [Fact]
        public async Task RefreshAsync_WithInvalidToken_ShouldFail()
        {
            // Act
            var result = await _authService.RefreshAsync("invalid-token", CancellationToken.None);

            // Assert
            result.IsSuccess.Should().BeFalse();
            result.Errors.Should().Contain(ErrorCodes.InvalidToken);
        }

        [Fact]
        public async Task RefreshAsync_WithRevokedToken_ShouldRevokeAllTokens()
        {
            // Arrange
            var email = "revoked@example.com";
            var password = "Password123";
            var registerResult = await _authService.RegisterAsync(email, password, CancellationToken.None);
            var refreshToken = registerResult.Value!.Token;

            // Revoke the token
            await _authService.LogoutAsync(refreshToken, CancellationToken.None);

            // Act - Try to use revoked token
            var result = await _authService.RefreshAsync(refreshToken, CancellationToken.None);

            // Assert
            result.IsSuccess.Should().BeFalse();
            result.Errors.Should().Contain(ErrorCodes.InvalidTokenReused);

            // Verify all tokens are revoked
            var user = await _dbContext.AuthUsers.FirstAsync(u => u.Email == email);
            var tokens = await _dbContext.AuthTokens
                .Where(t => t.UserId == user.Id)
                .ToListAsync();
            tokens.Should().AllSatisfy(t => t.IsRevoked.Should().BeTrue());
        }

        [Fact]
        public async Task RefreshAsync_ShouldRevokeOldToken()
        {
            // Arrange
            var email = "tokenrotation@example.com";
            var password = "Password123";
            var registerResult = await _authService.RegisterAsync(email, password, CancellationToken.None);
            var oldRefreshToken = registerResult.Value!.Token;

            // Act
            await _authService.RefreshAsync(oldRefreshToken, CancellationToken.None);

            // Assert - Old token should be revoked
            var user = await _dbContext.AuthUsers.FirstAsync(u => u.Email == email);
            var oldToken = await _dbContext.AuthTokens
                .Where(t => t.UserId == user.Id)
                .OrderBy(t => t.TokenExpiry)
                .FirstAsync();
            oldToken.IsRevoked.Should().BeTrue();
            oldToken.RevokedAt.Should().NotBeNull();
        }

        #endregion

        #region Logout Tests

        [Fact]
        public async Task LogoutAsync_ShouldRevokeToken()
        {
            // Arrange
            var email = "logout@example.com";
            var password = "Password123";
            var registerResult = await _authService.RegisterAsync(email, password, CancellationToken.None);
            var refreshToken = registerResult.Value!.Token;

            // Act
            var result = await _authService.LogoutAsync(refreshToken, CancellationToken.None);

            // Assert
            result.IsSuccess.Should().BeTrue();

            // Verify token is revoked
            var user = await _dbContext.AuthUsers.FirstAsync(u => u.Email == email);
            var token = await _dbContext.AuthTokens
                .FirstAsync(t => t.UserId == user.Id && t.TokenType == TokenType.Refresh);
            token.IsRevoked.Should().BeTrue();
            token.RevokedAt.Should().NotBeNull();
        }

        [Fact]
        public async Task LogoutAsync_WithAlreadyRevokedToken_ShouldSucceed()
        {
            // Arrange
            var email = "logout2@example.com";
            var password = "Password123";
            var registerResult = await _authService.RegisterAsync(email, password, CancellationToken.None);
            var refreshToken = registerResult.Value!.Token;
            await _authService.LogoutAsync(refreshToken, CancellationToken.None);

            // Act - Logout again
            var result = await _authService.LogoutAsync(refreshToken, CancellationToken.None);

            // Assert - Should be idempotent
            result.IsSuccess.Should().BeTrue();
        }

        [Fact]
        public async Task LogoutAllAsync_ShouldRevokeAllUserTokens()
        {
            // Arrange
            var email = "logoutall@example.com";
            var password = "Password123";
            await _authService.RegisterAsync(email, password, CancellationToken.None);

            // Create multiple sessions
            await _authService.LoginAsync(email, password, CancellationToken.None);
            var loginResult = await _authService.LoginAsync(email, password, CancellationToken.None);

            // Act
            var result = await _authService.LogoutAllAsync(loginResult.Value!.Token, CancellationToken.None);

            // Assert
            result.IsSuccess.Should().BeTrue();

            // Verify all tokens are revoked
            var user = await _dbContext.AuthUsers.FirstAsync(u => u.Email == email);
            var tokens = await _dbContext.AuthTokens
                .Where(t => t.UserId == user.Id && t.TokenType == TokenType.Refresh)
                .ToListAsync();
            tokens.Should().AllSatisfy(t => t.IsRevoked.Should().BeTrue());
        }

        #endregion

        #region Password Reset Tests

        [Fact]
        public async Task RequestPasswordResetAsync_WithValidEmail_ShouldReturnToken()
        {
            // Arrange
            var email = "reset@example.com";
            var password = "Password123";
            await _authService.RegisterAsync(email, password, CancellationToken.None);

            // Act
            var result = await _authService.RequestPasswordResetAsync(email, CancellationToken.None);

            // Assert
            result.IsSuccess.Should().BeTrue();
            result.Value.Should().NotBeNullOrEmpty();

            // Verify token in database
            var user = await _dbContext.AuthUsers.FirstAsync(u => u.Email == email);
            var token = await _dbContext.AuthTokens
                .FirstOrDefaultAsync(t => t.UserId == user.Id && t.TokenType == TokenType.PasswordReset);
            token.Should().NotBeNull();
            token!.IsRevoked.Should().BeFalse();
        }

        [Fact]
        public async Task RequestPasswordResetAsync_WithNonExistentEmail_ShouldReturnEmptySuccess()
        {
            // Act
            var result = await _authService.RequestPasswordResetAsync("nonexistent@example.com", CancellationToken.None);

            // Assert - Should succeed but return empty to prevent user enumeration
            result.IsSuccess.Should().BeTrue();
            result.Value.Should().BeEmpty();
        }

        [Fact]
        public async Task RequestPasswordResetAsync_ShouldRevokeOldResetTokens()
        {
            // Arrange
            var email = "resetmultiple@example.com";
            var password = "Password123";
            await _authService.RegisterAsync(email, password, CancellationToken.None);
            await _authService.RequestPasswordResetAsync(email, CancellationToken.None);

            // Act - Request another reset
            await _authService.RequestPasswordResetAsync(email, CancellationToken.None);

            // Assert - Old reset tokens should be revoked
            var user = await _dbContext.AuthUsers.FirstAsync(u => u.Email == email);
            var resetTokens = await _dbContext.AuthTokens
                .Where(t => t.UserId == user.Id && t.TokenType == TokenType.PasswordReset)
                .ToListAsync();
            resetTokens.Should().HaveCountGreaterThan(1);
            resetTokens.Count(t => !t.IsRevoked).Should().Be(1); // Only one active
        }

        [Fact]
        public async Task ResetPasswordAsync_WithValidToken_ShouldUpdatePassword()
        {
            // Arrange
            var email = "resetpwd@example.com";
            var oldPassword = "OldPassword123";
            var newPassword = "NewPassword123";

            await _authService.RegisterAsync(email, oldPassword, CancellationToken.None);
            var resetResult = await _authService.RequestPasswordResetAsync(email, CancellationToken.None);
            var resetToken = resetResult.Value!;

            // Act
            var result = await _authService.ResetPasswordAsync(resetToken, newPassword, CancellationToken.None);

            // Assert
            result.IsSuccess.Should().BeTrue();

            // Verify can login with new password
            var loginResult = await _authService.LoginAsync(email, newPassword, CancellationToken.None);
            loginResult.IsSuccess.Should().BeTrue();

            // Verify cannot login with old password
            var oldLoginResult = await _authService.LoginAsync(email, oldPassword, CancellationToken.None);
            oldLoginResult.IsSuccess.Should().BeFalse();
        }

        [Fact]
        public async Task ResetPasswordAsync_WithInvalidToken_ShouldFail()
        {
            // Act
            var result = await _authService.ResetPasswordAsync("invalid-token", "NewPassword123", CancellationToken.None);

            // Assert
            result.IsSuccess.Should().BeFalse();
            result.Errors.Should().Contain(ErrorCodes.InvalidToken);
        }

        [Fact]
        public async Task ResetPasswordAsync_ShouldRevokeAllRefreshTokens()
        {
            // Arrange
            var email = "resetrevoke@example.com";
            var password = "Password123";
            var newPassword = "NewPassword123";

            await _authService.RegisterAsync(email, password, CancellationToken.None);
            await _authService.LoginAsync(email, password, CancellationToken.None);

            var resetResult = await _authService.RequestPasswordResetAsync(email, CancellationToken.None);

            // Act
            await _authService.ResetPasswordAsync(resetResult.Value!, newPassword, CancellationToken.None);

            // Assert - All refresh tokens should be revoked
            var user = await _dbContext.AuthUsers.FirstAsync(u => u.Email == email);
            var refreshTokens = await _dbContext.AuthTokens
                .Where(t => t.UserId == user.Id && t.TokenType == TokenType.Refresh)
                .ToListAsync();
            refreshTokens.Should().AllSatisfy(t => t.IsRevoked.Should().BeTrue());
        }

        #endregion

        #region Email Verification Tests

        [Fact]
        public async Task VerifyEmailAsync_WithValidToken_ShouldVerifyEmail()
        {
            // Arrange
            var optionsWithVerification = TestAuthOptionsFactory.Create(emailVerificationRequired: true);
            var authSecurityService = new AuthSecurityService(optionsWithVerification);
            var tokenManagerService = new TokenManagerService(optionsWithVerification, authSecurityService);
            var roleStore = new RoleStore<int, TestUser, AuthRole<int>>(_dbContext);
            var tokenStore = new TokenStore<int, TestUser, AuthRole<int>>(_dbContext, options: optionsWithVerification);
            var userStore = new UserStore<int, TestUser, AuthRole<int>>(_dbContext);
            var roleManager = new RoleSeederService<int, TestUser, AuthRole<int>>(roleStore);

            await roleManager.SeedRolesAsync(optionsWithVerification.Value.Roles, CancellationToken.None);

            var authServiceWithVerification = new AuthService<int, TestUser, AuthRole<int>>(
                authSecurityService, _dbContext, optionsWithVerification, tokenManagerService, roleStore, userStore, tokenStore);

            var email = "verify@example.com";
            var password = "Password123";
            var registerResult = await authServiceWithVerification.RegisterAsync(email, password, CancellationToken.None);
            var verificationToken = registerResult.Value!.Token; // When verification required, this is the verification token

            // Act
            var result = await authServiceWithVerification.VerifyEmailAsync(verificationToken, CancellationToken.None);

            // Assert
            result.IsSuccess.Should().BeTrue();

            // Verify email is verified
            var user = await _dbContext.AuthUsers.FirstAsync(u => u.Email == email);
            user.IsEmailVerified.Should().BeTrue();
        }

        #endregion

        #region Admin Tests

        [Fact]
        public async Task RevokeAllUserTokens_ShouldRevokeAllTokens()
        {
            // Arrange
            var email = "admin@example.com";
            var password = "Password123";
            await _authService.RegisterAsync(email, password, CancellationToken.None);
            await _authService.LoginAsync(email, password, CancellationToken.None);

            var user = await _dbContext.AuthUsers.FirstAsync(u => u.Email == email);
            var tokenStore = new TokenStore<int, TestUser, AuthRole<int>>(_dbContext, _authOptions);
            // Act
            await tokenStore.RevokeUserTokens(user.Id, [TokenRevokationOption.All], CancellationToken.None);
            await _dbContext.SaveChangesAsync();

            // Assert
            var tokens = await _dbContext.AuthTokens
                .Where(t => t.UserId == user.Id)
                .ToListAsync();
            tokens.Should().AllSatisfy(t => t.IsRevoked.Should().BeTrue());
        }

        #endregion
    }
}
