namespace AuthLib.Common.Validators
{
    public static class EmailValidator
    {
        public static ValidationResult Validate(string email)
        {
            var emailValidationAttribute = new System.ComponentModel.DataAnnotations.EmailAddressAttribute();
            if (emailValidationAttribute.IsValid(email))
            {
                return ValidationResult.Success();
            }
            else
            {
                return ValidationResult.Failure("Invalid email format");
            }
        }
    }
}
