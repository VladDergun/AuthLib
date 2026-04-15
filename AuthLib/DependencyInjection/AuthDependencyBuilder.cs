using AuthLib.Options;
using Microsoft.Extensions.DependencyInjection;

namespace AuthLib.DependencyInjection
{
    /// <summary>
    /// Dependency builder class used for configuring authentication services and options.
    /// </summary>
    public sealed class AuthDependencyBuilder
    {
        public IServiceCollection Services { get; set; } = default!;
        public AuthOptions Options { get; set; } = default!;
    }
}
