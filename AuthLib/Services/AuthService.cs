using AuthLib.Common.AuthResults;
using AuthLib.Common.Builders;
using AuthLib.Common.Dtos;
using AuthLib.Common.Validators;
using AuthLib.Contexts;
using AuthLib.Enums;
using AuthLib.Extensions;
using AuthLib.Interfaces.Services;
using AuthLib.Models;
using AuthLib.Options;
using AuthLib.Services.IdGenerators;
using AuthLib.Services.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OtpNet;
using System.Data;


namespace AuthLib.Services
{
    internal class AuthService<TKey, TUser, TRole>(
        IAuthSecurityService authSecurityService,
        AuthDbContext<TKey, TUser, TRole> authDbContext,
        IOptions<AuthOptions> options,
        ITokenManagerService tokenManagerService,
        RoleStore<TKey, TUser, TRole> roleStore,
        UserStore<TKey, TUser, TRole> userStore,
        TokenStore<TKey, TUser, TRole> tokenStore,
        AuthErrorDescriber errorDescriber) : IAuthService<TUser>
            where TKey : IEquatable<TKey>
            where TUser : AuthUser<TKey, TRole>, new()
            where TRole : AuthRole<TKey>, new()
    {
        private readonly AuthDbContext<TKey, TUser, TRole> _authDbContext = authDbContext;
        private readonly IAuthSecurityService _authSecurityService = authSecurityService;
        private readonly RoleStore<TKey, TUser, TRole> _roleStore = roleStore;
        private readonly UserStore<TKey, TUser, TRole> _userStore = userStore;
        private readonly TokenStore<TKey, TUser, TRole> _tokenStore = tokenStore;

        private readonly ITokenManagerService _tokenManagerService = tokenManagerService;

        private readonly AuthOptions _authOptions = options.Value;
        private readonly AuthErrorDescriber _errors = errorDescriber;

        #region Login
        public async Task<Result<TokenReadDto>> LoginAsync(string email, string password, CancellationToken ct = default)
        {
            email = email.Trim().ToLowerInvariant();

            var validationResult = AuthValidator.ValidateEmailAndPassword(email, password, _authOptions.PasswordOptions);
            if (!validationResult.IsValid)
            {
                return validationResult.Errors.ToArray();
            }

            var user = await _userStore.Users
                .Where(u => u.Email == email)
                .Select(u => new
                {
                    u.Id,
                    u.HashedPassword,
                    EmailVerified = u.IsEmailVerified,
                    u.IsTwoFactorAuthEnabled
                })
                .FirstOrDefaultAsync(ct)
                .ConfigureAwait(false);

            if (user == null || user.HashedPassword == null)
            {
                return _errors.InvalidCredentials;
            }

            bool isPasswordValid = _authSecurityService.VerifyPassword(password, user.HashedPassword);
            if (!isPasswordValid)
            {
                return _errors.InvalidCredentials;
            }

            if (!user.EmailVerified)
            {
                return _errors.EmailNotVerified;
            }

            if (user.IsTwoFactorAuthEnabled)
            {
                await _tokenStore.RevokeUserTokens(user.Id, [TokenRevokationOption.TwoFactorAuth], ct)
                    .ConfigureAwait(false);

                var (twoFactorToken, twoFactorTokenHash) = _tokenManagerService.GenerateToken();
                _tokenStore.AddTwoFactorAuthToken(user.Id, twoFactorTokenHash);

                await _authDbContext.SaveChangesAsync(ct)
                    .ConfigureAwait(false);

                return new TokenReadDto(null, twoFactorToken, TokenType.TwoFactorAuth, user.Id.ToString());
            }

            var (token, tokenHash) = _tokenManagerService.GenerateToken();

            _tokenStore.AddRefreshToken(user.Id, tokenHash);

            await _authDbContext.SaveChangesAsync(ct)
                .ConfigureAwait(false);

            var roles = await _roleStore.GetUserRoleNamesAsync(user.Id, ct)
                .ConfigureAwait(false);

            string accessToken = _tokenManagerService.GenerateJWTToken(user.Id.ToString()!, email, roles: roles);

            return new TokenReadDto(accessToken, token, TokenType.Refresh, user.Id.ToString());
        }

        #endregion

        #region Registration

        public async Task<Result<TokenReadDto>> RegisterAsync(string email, string password, CancellationToken ct = default)
        {
            return await RegisterAsync(email, password, await _roleStore.GetDefaultAsync(ct), ct);
        }

        public async Task<Result<TokenReadDto>> RegisterAsync(string email, string password, string roleName, CancellationToken ct = default)
        {
            var role = await _roleStore.GetByNameAsync(roleName, ct)
                .ConfigureAwait(false);

            if(role is null)
            {
                return _errors.RoleNotFound;
            }

            return await RegisterAsync(email, password, role, ct);
        }

        public async Task<Result<TokenReadDto>> RegisterAsync(TUser user, string password, CancellationToken ct = default)
        {
            return await RegisterAsync(user, password, await _roleStore.GetDefaultAsync(ct).ConfigureAwait(false), ct)
                .ConfigureAwait(false);
        }

        public async Task<Result<TokenReadDto>> RegisterAsync(TUser user, string password, string roleName, CancellationToken ct = default)
        {
            var role = await _roleStore.GetByNameAsync(roleName, ct)
                .ConfigureAwait(false);

            if (role is null)
            {
                return _errors.RoleNotFound;
            }

            return await RegisterAsync(user, password, role, ct)
                .ConfigureAwait(false);
        }

        private async Task<Result<TokenReadDto>> RegisterAsync(string email, string password, TRole role, CancellationToken ct = default)
        {
            email = email.Trim().ToLowerInvariant();

            var validationResult = AuthValidator.ValidateEmailAndPassword(email, password, _authOptions.PasswordOptions);
            if (!validationResult.IsValid)
            {
                return validationResult.Errors.ToArray();
            }

            if (await _authDbContext.AuthUsers.AnyAsync(u => u.Email == email, ct)
                .ConfigureAwait(false))
            {
                return _errors.EmailAlreadyInUse;
            }

            string passwordHash = _authSecurityService.HashPassword(password);

            (string token, string tokenHash) = _tokenManagerService.GenerateToken();

            var user = new TUser
            {
                Id = IdGenerator<TKey>.IsAutoGenerated() ? default! : IdGenerator<TKey>.GenerateId(),
                Email = email,
                HashedPassword = passwordHash,
                IsEmailVerified = !_authOptions.EmailVerificationRequired,
                UserRoles =
                [
                    new() {
                        RoleId = role.Id
                    }
                ]
            };

            _authDbContext.AuthUsers.Add(user);

            try
            {
                await _authDbContext.SaveChangesAsync(ct)
                    .ConfigureAwait(false);
            }
            catch (DbUpdateException)
            {
                return _errors.EmailAlreadyInUse;
            }

            // Add token after user is saved and has a valid ID
            if (_authOptions.EmailVerificationRequired)
            {
                _tokenStore.AddEmailVerificationToken(user.Id, tokenHash);
            }
            else
            {
                _tokenStore.AddRefreshToken(user.Id, tokenHash);
            }

            await _authDbContext.SaveChangesAsync(ct)
                .ConfigureAwait(false);

            if (_authOptions.EmailVerificationRequired)
            {
                return new TokenReadDto(null, token, TokenType.EmailVerification, user.Id.ToString());
            }

            string accessToken = _tokenManagerService.GenerateJWTToken(user.Id.ToString() ?? "", user.Email, roles: [role.Name]);

            return new TokenReadDto(accessToken, token, TokenType.Refresh, user.Id.ToString());
        }

        private async Task<Result<TokenReadDto>> RegisterAsync(TUser user, string password, TRole role, CancellationToken ct = default)
        {
            ArgumentNullException.ThrowIfNull(user);

            user.Email = user.Email.Trim().ToLowerInvariant();

            var validationResult = AuthValidator.ValidateEmailAndPassword(user.Email, password, _authOptions.PasswordOptions);

            if (!validationResult.IsValid)
            {
                return validationResult.Errors.ToArray();
            }

            if (await _authDbContext.AuthUsers.AnyAsync(u => u.Email == user.Email, ct)
                .ConfigureAwait(false))
            {
                return _errors.EmailAlreadyInUse;
            }

            string passwordHash = _authSecurityService.HashPassword(password);

            (string token, string tokenHash) = _tokenManagerService.GenerateToken();

            user.Id = IdGenerator<TKey>.IsAutoGenerated() ? default! : IdGenerator<TKey>.GenerateId();
            user.HashedPassword = passwordHash;
            user.IsEmailVerified = !_authOptions.EmailVerificationRequired;
            user.UserRoles =
            [
                new() {
                    RoleId = role.Id
                }
            ];

            _authDbContext.AuthUsers.Add(user);

            try
            {
                await _authDbContext.SaveChangesAsync(ct)
                    .ConfigureAwait(false);
            }
            catch (DbUpdateException)
            {
                return _errors.EmailAlreadyInUse;
            }

            if (_authOptions.EmailVerificationRequired)
            {
                _tokenStore.AddEmailVerificationToken(user.Id, tokenHash);
            }
            else
            {
                _tokenStore.AddRefreshToken(user.Id, tokenHash);
            }

            await _authDbContext.SaveChangesAsync(ct)
                .ConfigureAwait(false);

            if (_authOptions.EmailVerificationRequired)
            {
                return new TokenReadDto(null, token, TokenType.EmailVerification, user.Id.ToString());
            }

            string accessToken = _tokenManagerService.GenerateJWTToken(user.Id.ToString() ?? "", user.Email, roles: [role.Name]);

            return new TokenReadDto(accessToken, token, TokenType.Refresh, user.Id.ToString());
        }

        #endregion

        #region Token Refresh
        public async Task<Result<TokenReadDto>> RefreshAsync(string refreshToken, CancellationToken ct = default)
        {
            var hash = _tokenManagerService.HashToken(refreshToken);

            var token = await _tokenStore.GetTokenAsync(hash, ct)
                .ConfigureAwait(false);

            if (token == null || token.TokenType != TokenType.Refresh)
                return _errors.InvalidToken;

            if (token.IsRevoked)
            {
                await _tokenStore.RevokeUserTokens(token.UserId, [TokenRevokationOption.All], ct)
                    .ConfigureAwait(false);
                return _errors.InvalidTokenReused;
            }

            if (token.TokenExpiry < DateTime.UtcNow)
                return _errors.TokenExpired;

            token.Revoke();

            var (newToken, newHash) = _tokenManagerService.GenerateToken();

            _tokenStore.AddRefreshToken(token.UserId, newHash);

            await _authDbContext.SaveChangesAsync(ct)
                .ConfigureAwait(false);

            var roles = await _roleStore.GetUserRoleNamesAsync(token.UserId, ct)
                .ConfigureAwait(false);

            var email = await _userStore.GetUserEmailAsync(token.UserId, ct)
                .ConfigureAwait(false);

            if (email is null)
            {
                return _errors.UserNotFound;
            }

            var accessToken = _tokenManagerService.GenerateJWTToken(token.UserId.ToString()!, email, roles: roles);

            return new TokenReadDto(accessToken, newToken, TokenType.Refresh, token.UserId.ToString());
        }

        #endregion

        #region Logout
        public async Task<Result> LogoutAsync(string refreshToken, CancellationToken ct = default)
        {
            var hash = _tokenManagerService.HashToken(refreshToken);

            var token = await _tokenStore.GetTokenAsync(hash, ct)
                .ConfigureAwait(false);

            if (token == null)
                return _errors.InvalidToken;

            if (token.IsRevoked)
                return Result.Success();

            token.Revoke();

            await _authDbContext.SaveChangesAsync(ct)
                .ConfigureAwait(false);

            return Result.Success();
        }

        public async Task<Result> LogoutAllAsync(string refreshToken, CancellationToken ct = default)
        {
            var hash = _tokenManagerService.HashToken(refreshToken);

            var token = await _tokenStore.GetTokenAsync(hash, ct)
                .ConfigureAwait(false);

            if (token == null)
                return _errors.InvalidToken;

            await _tokenStore.RevokeUserTokens(token.UserId, [TokenRevokationOption.Refresh], ct)
                .ConfigureAwait(false);

            await _authDbContext.SaveChangesAsync(ct)
                 .ConfigureAwait(false);

            return Result.Success();
        }

        #endregion

        #region Password Reset
        public async Task<Result<string>> RequestPasswordResetAsync(string email, CancellationToken ct = default)
        {
            email = email.Trim().ToLowerInvariant();

            var emailValidation = EmailValidator.Validate(email);

            if (!emailValidation.IsValid)
                return emailValidation.Errors.ToArray();

            var user = await _authDbContext.AuthUsers
                .FirstOrDefaultAsync(u => u.Email == email, ct)
                .ConfigureAwait(false);

            // Don't reveal if user exists (prevent user enumeration)
            if (user == null)
            {
                // Still return success to prevent user enumeration
                return Result<string>.Success(string.Empty);
            }

            // Revoke any existing password reset tokens for this user
            await _tokenStore.RevokeUserTokens(user.Id, [TokenRevokationOption.PasswordReset], ct)
                .ConfigureAwait(false);

            var (token, tokenHash) = _tokenManagerService.GenerateToken();

            _tokenStore.AddPasswordResetToken(user.Id, tokenHash);

            await _authDbContext.SaveChangesAsync(ct)
                .ConfigureAwait(false);

            // Return the token - library consumer will send it via email
            return Result<string>.Success(token);
        }

        public async Task<Result> ResetPasswordAsync(string token, string newPassword, CancellationToken ct = default)
        {
            var passwordValidation = PasswordValidator.Validate(newPassword, _authOptions.PasswordOptions);
            if (!passwordValidation.IsValid)
                return passwordValidation.Errors.ToArray();

            var hash = _tokenManagerService.HashToken(token);

            var authToken = await _tokenStore.GetTokenAsync(hash, ct)
                .ConfigureAwait(false);

            if (authToken == null || authToken.TokenType != TokenType.PasswordReset || authToken.IsRevoked)
                return _errors.InvalidToken;

            if (authToken.TokenExpiry < DateTime.UtcNow)
                return _errors.TokenExpired;

            //Get user
            var user = await _userStore.GetByIdAsync(authToken.UserId, ct)
                .ConfigureAwait(false);

            if(user is null)
            {
                return _errors.UserNotFound;
            }

            // Update password
            user.HashedPassword = _authSecurityService.HashPassword(newPassword);

            // Revoke the password reset token
            authToken.Revoke();

            // Revoke all password reset tokens for this user
            // Revoke all refresh tokens (force re-login on all devices)
            await _tokenStore.RevokeUserTokens(authToken.UserId, [TokenRevokationOption.PasswordReset, TokenRevokationOption.Refresh], ct)
                .ConfigureAwait(false);

            await _authDbContext.SaveChangesAsync(ct)
                .ConfigureAwait(false);

            return Result.Success();
        }

        #endregion

        #region Email verification
        public async Task<Result> VerifyEmailAsync(string token, CancellationToken ct = default)
        {
            var hash = _tokenManagerService.HashToken(token);

            var authToken = await _tokenStore.GetTokenAsync(hash, ct)
                .ConfigureAwait(false);

            if (authToken == null || authToken.TokenType != TokenType.EmailVerification || authToken.IsRevoked)
                return _errors.InvalidToken;
            if (authToken.TokenExpiry < DateTime.UtcNow)
                return _errors.TokenExpired;

            var user = await _userStore.GetByIdAsync(authToken.UserId, ct)
                .ConfigureAwait(false);

            if (user is null)
            {
                return _errors.UserNotFound;
            }

            if (user.IsEmailVerified)
            {
                return Result.Success();
            }

            user.IsEmailVerified = true;

            authToken.Revoke();

            await _tokenStore.RevokeUserTokens(authToken.UserId, [TokenRevokationOption.EmailVerification], ct)
                .ConfigureAwait(false);

            await _authDbContext.SaveChangesAsync(ct)
                .ConfigureAwait(false);

            return Result.Success();
        }

        #endregion

        #region Two-Factor Authentication

        public async Task<Result<TwoFactorSetupReadDto>> BeginTwoFactorSetupAsync(TUser user, CancellationToken ct = default)
        {
            if (_authOptions.EmailVerificationRequired && !user.IsEmailVerified)
                return _errors.EmailNotVerified;

            string key = TokenManagerService.GenerateTwoFactorAuthKey();

            string url = TOTPUrlBuilder.Build(key, _authOptions.TwoFactorAuthOptions!.Issuer, user.Email);

            string jwtToken = _tokenManagerService.GenerateJWTToken(
                user.Id.ToString()!,
                user.Email,
                expires: DateTime.UtcNow.Add(_authOptions.TwoFactorAuthOptions!.SetupTokenLifetime),
                additionalClaims: new Dictionary<string, string>
                {
                    ["type"] = "2fa_setup",
                    ["secret"] = key
                });

            return new TwoFactorSetupReadDto(jwtToken, url);
        }

        public async Task<Result> CompleteTwoFactorSetupAsync(TUser user, string token, string code, CancellationToken ct = default)
        {
            var principal = _tokenManagerService.ValidateJWTToken(token);

            if (principal == null || principal.Claims.FirstOrDefault(c => c.Type == "type" && c.Value == "2fa_setup") == null)
                return _errors.InvalidToken;

            var secretClaim = principal.Claims.FirstOrDefault(c => c.Type == "secret");
            if (secretClaim == null)
                return _errors.InvalidToken;

            var totp = new Totp(Base32Encoding.ToBytes(secretClaim.Value));

            var isValid = totp.VerifyTotp(code, out _, new VerificationWindow(1, 1));

            if (!isValid)
                return _errors.InvalidTwoFactorCode;

            user.TwoFactorAuthSecret = secretClaim.Value;
            user.IsTwoFactorAuthEnabled = true;

            await _authDbContext.SaveChangesAsync(ct)
                .ConfigureAwait(false);

            return Result.Success();
        }

        public async Task<Result<TokenReadDto>> VerifyTwoFactorCodeAsync(string twoFactorToken, string code, CancellationToken ct = default)
        {
            var hash = _tokenManagerService.HashToken(twoFactorToken);

            var token = await _tokenStore.GetTokenAsync(hash, ct)
                .ConfigureAwait(false);

            if (token == null || token.TokenType != TokenType.TwoFactorAuth)
                return _errors.InvalidToken;

            if (token.IsRevoked)
                return _errors.InvalidToken;

            if (token.TokenExpiry < DateTime.UtcNow)
                return _errors.TokenExpired;

            var user = await _userStore.GetByIdAsync(token.UserId, ct)
                .ConfigureAwait(false);

            if (user == null)
                return _errors.UserNotFound;

            if (!user.IsTwoFactorAuthEnabled || string.IsNullOrEmpty(user.TwoFactorAuthSecret))
                return _errors.TwoFactorNotEnabled;

            var totp = new Totp(Base32Encoding.ToBytes(user.TwoFactorAuthSecret));

            var isValid = totp.VerifyTotp(code, out _, new VerificationWindow(1, 1));

            if (!isValid)
                return _errors.InvalidTwoFactorCode;

            token.Revoke();

            await _tokenStore.RevokeUserTokens(token.UserId, [TokenRevokationOption.TwoFactorAuth], ct)
                .ConfigureAwait(false);

            var (refreshToken, refreshTokenHash) = _tokenManagerService.GenerateToken();

            _tokenStore.AddRefreshToken(token.UserId, refreshTokenHash);

            await _authDbContext.SaveChangesAsync(ct)
                .ConfigureAwait(false);

            var roles = await _roleStore.GetUserRoleNamesAsync(token.UserId, ct)
                .ConfigureAwait(false);

            var email = await _userStore.GetUserEmailAsync(token.UserId, ct)
                .ConfigureAwait(false);

            if (email is null)
            {
                return _errors.UserNotFound;
            }

            var accessToken = _tokenManagerService.GenerateJWTToken(token.UserId.ToString()!, email, roles: roles);

            return new TokenReadDto(accessToken, refreshToken, TokenType.Refresh, token.UserId.ToString());
        }

        public async Task<Result> DisableTwoFactorAuthAsync(TUser user, string password, CancellationToken ct = default)
        {
            if (!user.IsTwoFactorAuthEnabled)
                return _errors.TwoFactorNotEnabled;

            bool isPasswordValid = _authSecurityService.VerifyPassword(password, user.HashedPassword!);
            if (!isPasswordValid)
                return _errors.InvalidCredentials;

            user.IsTwoFactorAuthEnabled = false;
            user.TwoFactorAuthSecret = null;

            await _authDbContext.SaveChangesAsync(ct)
                .ConfigureAwait(false);

            return Result.Success();
        }

        #endregion


    }
}
