namespace AuthLib.Common.Validators
{
    public sealed class ValidationResult(IEnumerable<string> errors)
    {
        public bool IsValid => Errors.Count == 0;
        public IReadOnlyList<string> Errors { get; } = errors.ToList();

        public static ValidationResult Success() => new([]);
        public static ValidationResult Failure(params string[] errors)
            => new(errors);
    }
}
