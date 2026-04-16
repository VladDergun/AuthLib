namespace AuthLib.Common.AuthResults
{
    public static class ErrorCodes
    {
        public const string EmailAlreadyInUse = "Email is already in use.";
        public const string InvalidToken = "Invalid token.";
        public const string InvalidTokenReused = "Token reuse detected.";
        public const string TokenExpired = "Token expired.";
        public const string UserNotFound = "User not found.";
        public const string EmailNotVerified = "Email not verified.";
        public const string InvalidCredentials = "Invalid email or password.";
        public const string InvalidTwoFactorCode = "Invalid two-factor authentication code.";
        public const string TwoFactorRequired = "Two-factor authentication required.";
        public const string TwoFactorNotEnabled = "Two-factor authentication is not enabled.";
    }
}
