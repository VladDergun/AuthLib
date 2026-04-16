using AuthLib.Common.AuthResults;
using AuthLib.Common.Dtos;

namespace AuthLib.Interfaces.Services
{
    public interface IAuthService
    {
        /// <summary>
        /// Authenticates user with email and password
        /// </summary>
        /// <param name="email">User email</param>
        /// <param name="password">User password</param>
        /// <param name="ct">Cancellation Token</param>
        /// <returns></returns>
        Task<Result<TokenReadDto>> LoginAsync(string email, string password, CancellationToken ct = default);

        /// <summary>
        /// Registers the user with default role
        /// </summary>
        /// <param name="email">User email</param>
        /// <param name="password">User password</param>
        /// <param name="ct">Cancellation Token</param>
        /// <returns></returns>
        Task<Result<TokenReadDto>> RegisterAsync(string email, string password, CancellationToken ct = default);

        /// <summary>
        /// Registers user with specified role
        /// </summary>
        /// <param name="email">User email</param>
        /// <param name="password">User password</param>
        /// <param name="roleName">Role name</param>
        /// <param name="ct">Cancellation Token</param>
        /// <returns></returns>
        Task<Result<TokenReadDto>> RegisterAsync(string email, string password, string roleName, CancellationToken ct = default);

        /// <summary>
        /// Refreshes the access token using a valid refresh token
        /// </summary>
        /// <param name="refreshToken">Current refresh token</param>
        /// <param name="ct">Cancellation Token</param>
        /// <returns>New access token and refresh token if successful</returns>
        /// <remarks>
        /// This method implements token rotation - the old refresh token is revoked and a new one is issued.
        /// If a revoked token is reused, all user tokens are revoked for security.
        /// </remarks>
        Task<Result<TokenReadDto>> RefreshAsync(string refreshToken, CancellationToken ct = default);

        /// <summary>
        /// Logs out from the current device by revoking the refresh token
        /// </summary>
        /// <param name="refreshToken">Refresh token to revoke</param>
        /// <param name="ct">Cancellation Token</param>
        /// <returns></returns>
        Task<Result> LogoutAsync(string refreshToken, CancellationToken ct = default);

        /// <summary>
        /// Logs out from all devices by revoking all user's refresh tokens
        /// </summary>
        /// <param name="refreshToken">Current refresh token to identify the user</param>
        /// <param name="ct">Cancellation Token</param>
        /// <returns></returns>
        Task<Result> LogoutAllAsync(string refreshToken, CancellationToken ct = default);

        /// <summary>
        /// Generates a password reset token for the user
        /// </summary>
        /// <param name="email">User email</param>
        /// <param name="ct">Cancellation Token</param>
        /// <returns>Password reset token (library consumer sends this via email)</returns>
        Task<Result<string>> RequestPasswordResetAsync(string email, CancellationToken ct = default);

        /// <summary>
        /// Resets user password using the password reset token
        /// </summary>
        /// <param name="token">Password reset token</param>
        /// <param name="newPassword">New password</param>
        /// <param name="ct">Cancellation Token</param>
        /// <returns></returns>
        Task<Result> ResetPasswordAsync(string token, string newPassword, CancellationToken ct = default);

        /// <summary>
        /// Verifies a user's email address using an email verification token
        /// </summary>
        /// <param name="token">Email verification token</param>
        /// <param name="ct">Cancellation Token</param>
        /// <returns>Success if email is verified, error codes otherwise</returns>
        /// <remarks>
        /// After successful verification, all email verification tokens for the user are revoked.
        /// </remarks>
        Task<Result> VerifyEmailAsync(string token, CancellationToken ct = default);

        /// <summary>
        /// Verifies a two-factor authentication code and completes the login process
        /// </summary>
        /// <param name="twoFactorToken">Two-factor authentication token from login</param>
        /// <param name="code">Six-digit 2FA code from authenticator app</param>
        /// <param name="ct">Cancellation Token</param>
        /// <returns>Access token and refresh token if successful</returns>
        /// <remarks>
        /// This method should be called after LoginAsync returns a TwoFactorAuth token type.
        /// After successful verification, all 2FA tokens for the user are revoked.
        /// </remarks>
        Task<Result<TokenReadDto>> VerifyTwoFactorCodeAsync(string twoFactorToken, string code, CancellationToken ct = default);
    }

    public interface IAuthService<TUser> : IAuthService
    {
        /// <summary>
        /// Registers a user with the provided user object and password, using the default role
        /// </summary>
        /// <param name="user">User object to register</param>
        /// <param name="password">User password</param>
        /// <param name="ct">Cancellation Token</param>
        /// <returns></returns>
        Task<Result<TokenReadDto>> RegisterAsync(TUser user, string password, CancellationToken ct = default);

        /// <summary>
        /// Registers a user with the provided user object, password, and specified role
        /// </summary>
        /// <param name="user">User object to register</param>
        /// <param name="password">User password</param>
        /// <param name="roleName">Role name to assign to the user</param>
        /// <param name="ct">Cancellation Token</param>
        /// <returns></returns>
        Task<Result<TokenReadDto>> RegisterAsync(TUser user, string password, string roleName, CancellationToken ct = default);

        /// <summary>
        /// Begins the two-factor authentication setup process for a user
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <param name="ct">Cancellation Token</param>
        /// <returns>Setup token and QR code URL for authenticator app configuration</returns>
        /// <remarks>
        /// The returned setup token must be passed to CompleteTwoFactorSetupAsync along with a verification code.
        /// The QR code URL can be displayed to the user for scanning with an authenticator app.
        /// </remarks>
        Task<Result<TwoFactorSetupReadDto>> BeginTwoFactorSetupAsync(TUser user, CancellationToken ct = default);

        /// <summary>
        /// Completes the two-factor authentication setup by verifying the code
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <param name="token">Setup token from BeginTwoFactorSetupAsync</param>
        /// <param name="code">Six-digit verification code from authenticator app</param>
        /// <param name="ct">Cancellation Token</param>
        /// <returns>Success if 2FA is enabled, error codes otherwise</returns>
        Task<Result> CompleteTwoFactorSetupAsync(TUser user, string token, string code, CancellationToken ct = default);

        /// <summary>
        /// Disables two-factor authentication for a user
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <param name="password">User's password for verification</param>
        /// <param name="ct">Cancellation Token</param>
        /// <returns>Success if 2FA is disabled, error codes otherwise</returns>
        /// <remarks>
        /// Requires password verification for security. Removes the 2FA secret from the user account.
        /// </remarks>
        Task<Result> DisableTwoFactorAuthAsync(TUser user, string password, CancellationToken ct = default);
    }
}
