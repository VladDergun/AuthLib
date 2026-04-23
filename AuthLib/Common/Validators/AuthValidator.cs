using AuthLib.Options;

namespace AuthLib.Common.Validators
{
    public static class AuthValidator
    {
        public static ValidationResult ValidateEmailAndPassword(string email, string password, PasswordOptions? passwordOptions)
        {
            var emailValidation = EmailValidator.Validate(email);
            if (!emailValidation.IsValid)
                return emailValidation;

            if(passwordOptions != null)
            {
                var passwordValidation = PasswordValidator.Validate(password, passwordOptions);
                if (!passwordValidation.IsValid)
                    return passwordValidation;
            }

            return ValidationResult.Success();
        }
    }
}
