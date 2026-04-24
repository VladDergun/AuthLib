using AuthLib.Interfaces.Services;
using AuthLib.Options;
using AuthLib.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AuthLib.DependencyInjection
{
    /// <summary>
    /// Entry-point extensions on <see cref="IServiceCollection"/> for wiring AuthLib.
    /// </summary>
    public static class AuthServiceCollectionExtensions
    {
        /// <summary>
        /// Registers the core AuthLib services (security, token manager, default error describer)
        /// and returns a fluent <see cref="AuthDependencyBuilder"/> for further configuration
        /// (stores, JWT authentication, custom error describer, ...).
        /// </summary>
        /// <param name="services">The application service collection.</param>
        /// <param name="options">Authentication options. Captured by reference; treat as immutable after this call.</param>
        public static AuthDependencyBuilder AddAuthServices(
            this IServiceCollection services,
            AuthOptions options)
        {
            ArgumentNullException.ThrowIfNull(services);
            ArgumentNullException.ThrowIfNull(options);

            services.AddSingleton(Microsoft.Extensions.Options.Options.Create(options));

            services.TryAddScoped<IAuthSecurityService, AuthSecurityService>();
            services.TryAddScoped<ITokenManagerService, TokenManagerService>();
            services.TryAddScoped<AuthErrorDescriber>();

            return new AuthDependencyBuilder
            {
                Services = services,
                Options = options
            };
        }
    }
}
