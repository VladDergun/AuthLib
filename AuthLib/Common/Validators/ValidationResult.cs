namespace AuthLib.Common.Validators
{
    public sealed class ValidationResult
    {
        public bool IsValid => Errors.Count == 0;
        public IReadOnlyList<string> Errors { get; }

        public ValidationResult(IEnumerable<string> errors)
        {
            Errors = errors.ToList();
        }

        public static ValidationResult Success() => new([]);
        public static ValidationResult Failure(params string[] errors)
            => new(errors);
    }
}
