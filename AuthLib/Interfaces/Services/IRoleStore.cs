namespace AuthLib.Interfaces.Services
{
    public interface IRoleStore<TRole>
        where TRole : class
    {
        /// <summary>
        /// Gets a role by its name. Returns null if the role does not exist.
        /// </summary>
        /// <param name="roleName">Role name</param>
        /// <param name="ct">Cancellation token</param>
        /// <returns>The role if found, otherwise null</returns>
        Task<TRole?> GetByNameAsync(string roleName, CancellationToken ct = default!);
        /// <summary>
        /// Gets the default role. Throws an exception if the default role is not found.
        /// </summary>
        /// <param name="ct">Cancellation token</param>
        /// <returns>Default role</returns>
        /// <exception cref="InvalidOperationException">Thrown if the default role is not found</exception>
        Task<TRole> GetDefaultAsync(CancellationToken ct = default!);
        /// <summary>
        /// Gets all roles. Returns an empty collection if no roles are found.
        /// </summary>
        /// <param name="ct">Cancellation token</param>
        /// <returns>All roles</returns>
        Task<IReadOnlyCollection<TRole>> GetAllAsync(CancellationToken ct = default!);
        /// <summary>
        /// Gets the names of the roles assigned to a user. Returns an empty collection if the user has no roles.
        /// </summary>
        /// <param name="userId">User ID</param>
        /// <param name="ct">Cancellation token</param>
        /// <returns>Names of the roles assigned to the user</returns>
        Task<IReadOnlyCollection<string>> GetUserRoleNamesAsync(string userId, CancellationToken ct = default!);
    }
}
