namespace AuthLib.Services
{
    /// <summary>
    /// Service providing the default human-readable messages used by auth services
    /// when an operation fails. Derive from this class and override any property to localize or customize
    /// the messages, then register your implementation via
    /// <c>AuthDependencyBuilder.AddErrorDescriber&lt;TDescriber&gt;()</c>.
    /// </summary>
    public class AuthErrorDescriber
    {
        public virtual string EmailAlreadyInUse => "Email is already in use.";
        public virtual string InvalidToken => "Invalid token.";
        public virtual string InvalidTokenReused => "Token reuse detected.";
        public virtual string TokenExpired => "Token expired.";
        public virtual string UserNotFound => "User not found.";
        public virtual string RoleNotFound => "Role not found.";
        public virtual string EmailNotVerified => "Email not verified.";
        public virtual string InvalidCredentials => "Invalid email or password.";
        public virtual string InvalidTwoFactorCode => "Invalid two-factor authentication code.";
        public virtual string TwoFactorRequired => "Two-factor authentication required.";
        public virtual string TwoFactorNotEnabled => "Two-factor authentication is not enabled.";
    }
}
