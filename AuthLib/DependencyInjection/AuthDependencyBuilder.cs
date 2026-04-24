using AuthLib.Options;
using Microsoft.Extensions.DependencyInjection;

namespace AuthLib.DependencyInjection
{
    /// <summary>
    /// Dependency builder class used for configuring authentication services and options.
    /// </summary>
    public sealed class AuthDependencyBuilder
    {
        /// <summary>
        /// The service collection that AuthLib registrations are written to.
        /// </summary>
        public required IServiceCollection Services { get; init; }

        /// <summary>
        /// The resolved <see cref="AuthOptions"/> snapshot used to configure AuthLib.
        /// </summary>
        public required AuthOptions Options { get; init; }
    }
}
