using AuthLib.Options;

namespace AuthLib.Common.Validators
{
    public static class PasswordValidator
    {
        public static ValidationResult Validate(string password, PasswordOptions? options)
        {
            if(options is null)
                return ValidationResult.Success();

            var errors = new List<string>();

            if (password.Length < options.RequireMinLength)
                errors.Add($"Minimum length is {options.RequireMinLength}");

            if (password.Length > options.RequireMaxLength)
                errors.Add($"Maximum length is {options.RequireMaxLength}");

            if (Count(password, char.IsDigit) < options.RequireDigitCount)
                errors.Add("Not enough digits");

            if (Count(password, char.IsUpper) < options.RequireUppercaseCount)
                errors.Add("Not enough uppercase letters");

            if (Count(password, char.IsLower) < options.RequireLowercaseCount)
                errors.Add("Not enough lowercase letters");

            if (Count(password, c => !char.IsLetterOrDigit(c)) < options.RequireNonAlphanumericCount)
                errors.Add("Not enough special characters");

            if (options.RequireRegexValidation is not null &&
                !options.RequireRegexValidation.IsMatch(password))
                errors.Add("Password does not match required pattern");

            if (options.AllowedSpecialSymbols is not null)
            {
                var invalid = password
                    .Where(c => !char.IsLetterOrDigit(c) && !options.AllowedSpecialSymbols.Contains(c));

                if (invalid.Any())
                    errors.Add("Contains invalid special characters");
            }

            return new ValidationResult(errors);
        }

        private static int Count(string input, Func<char, bool> predicate)
            => input.Count(predicate);
    }
}
