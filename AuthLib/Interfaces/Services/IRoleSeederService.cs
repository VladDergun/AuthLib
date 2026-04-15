using AuthLib.Options;

namespace AuthLib.Interfaces.Services
{
    internal interface IRoleSeederService
    {
        Task SeedRolesAsync(IReadOnlyList<Role> roles, CancellationToken ct);
    }
}
