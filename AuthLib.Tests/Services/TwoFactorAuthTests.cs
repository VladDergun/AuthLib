using AuthLib.Common.AuthResults;
using AuthLib.Enums;
using AuthLib.Interfaces.Services;
using AuthLib.Models;
using AuthLib.Options;
using AuthLib.Services;
using AuthLib.Services.Stores;
using AuthLib.Tests.Helpers;
using FluentAssertions;
using Microsoft.Extensions.Options;
using OtpNet;

namespace AuthLib.Tests.Services
{
    public class TwoFactorAuthTests(PostgreSqlContainerFixture fixture) : IClassFixture<PostgreSqlContainerFixture>, IAsyncLifetime
    {
        private readonly PostgreSqlContainerFixture _fixture = fixture;
        private TestDbContext _dbContext = null!;
        private IAuthService<TestUser> _authService = null!;
        private IOptions<AuthOptions> _authOptions = null!;
        private UserStore<int, TestUser, AuthRole<int>> _userStore = null!;

        public async ValueTask InitializeAsync()
        {
            _dbContext = TestDbContextFactory.CreateContext(_fixture.ConnectionString);
            _authOptions = TestAuthOptionsFactory.Create(twoFactorAuthOptions: new TwoFactorAuthOptions
            {
                Issuer = "TestApp",
                SetupTokenLifetime = TimeSpan.FromMinutes(5),
                TwoFactorTokenLifetime = TimeSpan.FromMinutes(5)
            });

            var authSecurityService = new AuthSecurityService(_authOptions);
            var tokenManagerService = new TokenManagerService(_authOptions, authSecurityService);
            var roleStore = new RoleStore<int, TestUser, AuthRole<int>>(_dbContext);
            var tokenStore = new TokenStore<int, TestUser, AuthRole<int>>(_dbContext, options: _authOptions);
            _userStore = new UserStore<int, TestUser, AuthRole<int>>(_dbContext);
            var roleManager = new RoleSeederService<int, TestUser, AuthRole<int>>(roleStore);

            await roleManager.SeedRolesAsync(_authOptions.Value.Roles, CancellationToken.None);

            _authService = new AuthService<int, TestUser, AuthRole<int>>(
                authSecurityService,
                _dbContext,
                _authOptions,
                tokenManagerService,
                roleStore,
                _userStore,
                tokenStore);
        }

        public async ValueTask DisposeAsync()
        {
            await _dbContext.Database.EnsureDeletedAsync();
            await _dbContext.DisposeAsync();
        }

        [Fact]
        public async Task BeginTwoFactorSetupAsync_ShouldReturnQrCodeAndToken()
        {
            var registerResult = await _authService.RegisterAsync("user@test.com", "Password123!", TestContext.Current.CancellationToken);
            registerResult.IsSuccess.Should().BeTrue();
            registerResult.Value.Should().NotBeNull();
            registerResult.Value.UserId.Should().NotBeNull();

            var user = await _userStore.GetByIdAsync(registerResult.Value.UserId, TestContext.Current.CancellationToken);

            var result = await _authService.BeginTwoFactorSetupAsync(user!, TestContext.Current.CancellationToken);

            result.IsSuccess.Should().BeTrue();
            result.Value.Should().NotBeNull();
            result.Value!.QRCodeUri.Should().StartWith("otpauth://totp/");
            result.Value.QRCodeUri.Should().Contain("TestApp");
            result.Value.QRCodeUri.Should().Contain(Uri.EscapeDataString("user@test.com"));
            result.Value.JWTToken.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public async Task CompleteTwoFactorSetupAsync_WithValidCode_ShouldEnableTwoFactor()
        {
            var registerResult = await _authService.RegisterAsync("user@test.com", "Password123!", TestContext.Current.CancellationToken);
            registerResult.IsSuccess.Should().BeTrue();
            registerResult.Value.Should().NotBeNull();
            registerResult.Value.UserId.Should().NotBeNull();

            var user = await _userStore.GetByIdAsync(registerResult.Value.UserId, TestContext.Current.CancellationToken);

            var setupResult = await _authService.BeginTwoFactorSetupAsync(user!, TestContext.Current.CancellationToken);
            var secret = ExtractSecretFromQrUrl(setupResult.Value!.QRCodeUri);
            var totp = new Totp(Base32Encoding.ToBytes(secret));
            var code = totp.ComputeTotp();

            var completeResult = await _authService.CompleteTwoFactorSetupAsync(user!, setupResult.Value.JWTToken, code, TestContext.Current.CancellationToken);

            completeResult.IsSuccess.Should().BeTrue();
            await _dbContext.Entry(user).ReloadAsync(TestContext.Current.CancellationToken);
            user.IsTwoFactorAuthEnabled.Should().BeTrue();
            user.TwoFactorAuthSecret.Should().Be(secret);
        }

        [Fact]
        public async Task CompleteTwoFactorSetupAsync_WithInvalidCode_ShouldReturnError()
        {
            var registerResult = await _authService.RegisterAsync("user@test.com", "Password123!", TestContext.Current.CancellationToken);
            registerResult.IsSuccess.Should().BeTrue();
            registerResult.Value.Should().NotBeNull();
            registerResult.Value.UserId.Should().NotBeNull();

            var user = await _userStore.GetByIdAsync(registerResult.Value.UserId, TestContext.Current.CancellationToken);

            var setupResult = await _authService.BeginTwoFactorSetupAsync(user!, TestContext.Current.CancellationToken);

            var completeResult = await _authService.CompleteTwoFactorSetupAsync(user!, setupResult.Value!.JWTToken, "000000", TestContext.Current.CancellationToken);

            completeResult.IsSuccess.Should().BeFalse();
            completeResult.Errors.Should().Contain(ErrorCodes.InvalidTwoFactorCode);
        }

        [Fact]
        public async Task LoginAsync_WithTwoFactorEnabled_ShouldReturnTwoFactorToken()
        {
            var registerResult = await _authService.RegisterAsync("user@test.com", "Password123!", TestContext.Current.CancellationToken);
            registerResult.IsSuccess.Should().BeTrue();
            registerResult.Value.Should().NotBeNull();
            registerResult.Value.UserId.Should().NotBeNull();

            var user = await _userStore.GetByIdAsync(registerResult.Value.UserId, TestContext.Current.CancellationToken);

            var setupResult = await _authService.BeginTwoFactorSetupAsync(user!, TestContext.Current.CancellationToken);
            var secret = ExtractSecretFromQrUrl(setupResult.Value!.QRCodeUri);
            var totp = new Totp(Base32Encoding.ToBytes(secret));
            var code = totp.ComputeTotp();
            await _authService.CompleteTwoFactorSetupAsync(user!, setupResult.Value.JWTToken, code, TestContext.Current.CancellationToken);

            var loginResult = await _authService.LoginAsync("user@test.com", "Password123!", TestContext.Current.CancellationToken);

            loginResult.IsSuccess.Should().BeTrue();
            loginResult.Value!.AccessToken.Should().BeNull();
            loginResult.Value.Token.Should().NotBeNullOrEmpty();
            loginResult.Value.TokenType.Should().Be(TokenType.TwoFactorAuth);
        }

        [Fact]
        public async Task VerifyTwoFactorCodeAsync_WithValidCode_ShouldReturnAccessToken()
        {
            var registerResult = await _authService.RegisterAsync("user@test.com", "Password123!", TestContext.Current.CancellationToken);
            registerResult.IsSuccess.Should().BeTrue();
            registerResult.Value.Should().NotBeNull();
            registerResult.Value.UserId.Should().NotBeNull();

            var user = await _userStore.GetByIdAsync(registerResult.Value.UserId, TestContext.Current.CancellationToken);

            var setupResult = await _authService.BeginTwoFactorSetupAsync(user!, TestContext.Current.CancellationToken);
            var secret = ExtractSecretFromQrUrl(setupResult.Value!.QRCodeUri);
            var totp = new Totp(Base32Encoding.ToBytes(secret));
            var setupCode = totp.ComputeTotp();
            await _authService.CompleteTwoFactorSetupAsync(user!, setupResult.Value.JWTToken, setupCode, TestContext.Current.CancellationToken);

            var loginResult = await _authService.LoginAsync("user@test.com", "Password123!", TestContext.Current.CancellationToken);
            var verifyCode = totp.ComputeTotp();

            var verifyResult = await _authService.VerifyTwoFactorCodeAsync(loginResult.Value!.Token, verifyCode, TestContext.Current.CancellationToken);

            verifyResult.IsSuccess.Should().BeTrue();
            verifyResult.Value!.AccessToken.Should().NotBeNullOrEmpty();
            verifyResult.Value.Token.Should().NotBeNullOrEmpty();
            verifyResult.Value.TokenType.Should().Be(TokenType.Refresh);
        }

        [Fact]
        public async Task VerifyTwoFactorCodeAsync_WithInvalidCode_ShouldReturnError()
        {
            var registerResult = await _authService.RegisterAsync("user@test.com", "Password123!", TestContext.Current.CancellationToken);
            registerResult.IsSuccess.Should().BeTrue();
            registerResult.Value.Should().NotBeNull();
            registerResult.Value.UserId.Should().NotBeNull();

            var user = await _userStore.GetByIdAsync(registerResult.Value.UserId, TestContext.Current.CancellationToken);

            var setupResult = await _authService.BeginTwoFactorSetupAsync(user!, TestContext.Current.CancellationToken);
            var secret = ExtractSecretFromQrUrl(setupResult.Value!.QRCodeUri);
            var totp = new Totp(Base32Encoding.ToBytes(secret));
            var code = totp.ComputeTotp();
            await _authService.CompleteTwoFactorSetupAsync(user!, setupResult.Value.JWTToken, code, TestContext.Current.CancellationToken);

            var loginResult = await _authService.LoginAsync("user@test.com", "Password123!", TestContext.Current.CancellationToken);

            var verifyResult = await _authService.VerifyTwoFactorCodeAsync(loginResult.Value!.Token, "000000", TestContext.Current.CancellationToken);

            verifyResult.IsSuccess.Should().BeFalse();
            verifyResult.Errors.Should().Contain(ErrorCodes.InvalidTwoFactorCode);
        }

        [Fact]
        public async Task DisableTwoFactorAuthAsync_WithValidPassword_ShouldDisableTwoFactor()
        {
            var registerResult = await _authService.RegisterAsync("user@test.com", "Password123!", TestContext.Current.CancellationToken);
            registerResult.IsSuccess.Should().BeTrue();
            registerResult.Value.Should().NotBeNull();
            registerResult.Value.UserId.Should().NotBeNull();

            var user = await _userStore.GetByIdAsync(registerResult.Value.UserId, TestContext.Current.CancellationToken);

            var setupResult = await _authService.BeginTwoFactorSetupAsync(user!, TestContext.Current.CancellationToken);
            var secret = ExtractSecretFromQrUrl(setupResult.Value!.QRCodeUri);
            var totp = new Totp(Base32Encoding.ToBytes(secret));
            var code = totp.ComputeTotp();
            await _authService.CompleteTwoFactorSetupAsync(user!, setupResult.Value.JWTToken, code, TestContext.Current.CancellationToken);

            var disableResult = await _authService.DisableTwoFactorAuthAsync(user!, "Password123!", TestContext.Current.CancellationToken);

            disableResult.IsSuccess.Should().BeTrue();
            await _dbContext.Entry(user).ReloadAsync(TestContext.Current.CancellationToken);
            user.IsTwoFactorAuthEnabled.Should().BeFalse();
            user.TwoFactorAuthSecret.Should().BeNull();
        }

        [Fact]
        public async Task DisableTwoFactorAuthAsync_WithInvalidPassword_ShouldReturnError()
        {
            var registerResult = await _authService.RegisterAsync("user@test.com", "Password123!", TestContext.Current.CancellationToken);
            registerResult.IsSuccess.Should().BeTrue();
            registerResult.Value.Should().NotBeNull();
            registerResult.Value.UserId.Should().NotBeNull();

            var user = await _userStore.GetByIdAsync(registerResult.Value.UserId, TestContext.Current.CancellationToken);

            var setupResult = await _authService.BeginTwoFactorSetupAsync(user!, TestContext.Current.CancellationToken);
            var secret = ExtractSecretFromQrUrl(setupResult.Value!.QRCodeUri);
            var totp = new Totp(Base32Encoding.ToBytes(secret));
            var code = totp.ComputeTotp();
            await _authService.CompleteTwoFactorSetupAsync(user!, setupResult.Value.JWTToken, code, TestContext.Current.CancellationToken);

            var disableResult = await _authService.DisableTwoFactorAuthAsync(user!, "WrongPassword!", TestContext.Current.CancellationToken);

            disableResult.IsSuccess.Should().BeFalse();
            disableResult.Errors.Should().Contain(ErrorCodes.InvalidCredentials);
        }

        [Fact]
        public async Task LoginAsync_WithTwoFactorEnabled_ShouldRevokePreviousTwoFactorTokens()
        {
            var registerResult = await _authService.RegisterAsync("user@test.com", "Password123!", TestContext.Current.CancellationToken);
            registerResult.IsSuccess.Should().BeTrue();
            registerResult.Value.Should().NotBeNull();
            registerResult.Value.UserId.Should().NotBeNull();

            var user = await _userStore.GetByIdAsync(registerResult.Value.UserId, TestContext.Current.CancellationToken);

            var setupResult = await _authService.BeginTwoFactorSetupAsync(user!, TestContext.Current.CancellationToken);
            var secret = ExtractSecretFromQrUrl(setupResult.Value!.QRCodeUri);
            var totp = new Totp(Base32Encoding.ToBytes(secret));
            var code = totp.ComputeTotp();
            await _authService.CompleteTwoFactorSetupAsync(user!, setupResult.Value.JWTToken, code, TestContext.Current.CancellationToken); 
            var firstLogin = await _authService.LoginAsync("user@test.com", "Password123!", TestContext.Current.CancellationToken);
            var firstToken = firstLogin.Value!.Token;

            var secondLogin = await _authService.LoginAsync("user@test.com", "Password123!", TestContext.Current.CancellationToken);

            var verifyCode = totp.ComputeTotp();
            var verifyResult = await _authService.VerifyTwoFactorCodeAsync(firstToken, verifyCode, TestContext.Current.CancellationToken);

            verifyResult.IsSuccess.Should().BeFalse();
            verifyResult.Errors.Should().Contain(ErrorCodes.InvalidToken);
        }

        private static string ExtractSecretFromQrUrl(string qrUrl)
        {
            var secretParam = qrUrl.Split('?')[1].Split('&')
                .First(p => p.StartsWith("secret="));
            return secretParam.Split('=')[1];
        }
    }
}
