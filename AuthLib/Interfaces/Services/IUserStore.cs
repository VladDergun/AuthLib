namespace AuthLib.Interfaces.Services
{
    public interface IUserStore<TUser>
    {
        /// <summary>
        /// Gets a user by their ID
        /// </summary>
        /// <param name="id">User ID as string</param>
        /// <param name="ct">Cancellation Token</param>
        /// <returns>User object</returns>
        /// <exception cref="InvalidOperationException">Thrown when user is not found</exception>
        Task<TUser> GetByIdAsync(string id, CancellationToken ct = default);

        /// <summary>
        /// Gets a user's email by their ID
        /// </summary>
        /// <param name="id">User ID as string</param>
        /// <param name="ct">Cancellation Token</param>
        /// <returns>User email</returns>
        /// <exception cref="InvalidOperationException">Thrown when user is not found</exception>
        Task<string> GetUserEmailAsync(string id, CancellationToken ct = default);
    }
}
