namespace AuthLib.Common.AuthResults
{
    public class Result
    {
        public bool IsSuccess { get; }
        public IReadOnlyList<string> Errors { get; }

        protected Result(bool isSuccess, IEnumerable<string>? errors = null)
        {
            IsSuccess = isSuccess;
            Errors = errors?.ToList() ?? [];
        }

        public static Result Success() => new(true);

        public static Result Failure(params string[] errors)
            => new(false, errors);

        public static implicit operator Result(string error)
    => Failure(error);

        public static implicit operator Result(string[] errors)
            => Failure(errors);
    }

    public class Result<T> : Result
    {
        public T? Value { get; }

        private Result(T value) : base(true)
        {
            Value = value;
        }

        private Result(IEnumerable<string> errors) : base(false, errors) { }

        public static Result<T> Success(T value) => new(value);

        public static new Result<T> Failure(params string[] errors)
            => new(errors);

        public static implicit operator Result<T>(T value)
       => Success(value);

        public static implicit operator Result<T>(string error)
            => Failure(error);

        public static implicit operator Result<T>(string[] errors)
            => Failure(errors);
    }
}
