using AuthLib.Contexts;
using AuthLib.Interfaces;
using AuthLib.Interfaces.Services;
using AuthLib.Models;
using AuthLib.Services;
using AuthLib.Services.Hosted;
using AuthLib.Services.Stores;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace AuthLib.DependencyInjection
{
    /// <summary>
    /// Fluent extensions on <see cref="AuthDependencyBuilder"/> for composing the AuthLib pipeline.
    /// </summary>
    public static class AuthBuilderExtensions
    {
        /// <summary>
        /// Registers the EF Core-backed stores (user, role, token) and the public <c>IAuthService</c>
        /// implementations based on the generic arguments of <typeparamref name="TDbContext"/>.
        /// </summary>
        public static AuthDependencyBuilder AddEntityFrameworkStores<TDbContext>(
            this AuthDependencyBuilder builder)
            where TDbContext : DbContext, IAuthDbContext
        {
            ArgumentNullException.ThrowIfNull(builder);

            var types = ResolveAuthDbContextTypes(typeof(TDbContext))
                ?? throw new InvalidOperationException(
                    $"{typeof(TDbContext).Name} must inherit from AuthDbContext<TKey, TUser, TRole>.");

            var (keyType, userType, roleType) = types;
            keyType ??= typeof(string);
            roleType ??= typeof(AuthRole<>).MakeGenericType(keyType);

            RegisterDbContextAliases(builder.Services, typeof(TDbContext), keyType, userType, roleType);
            RegisterAuthServices(builder.Services, keyType, userType, roleType);
            RegisterStores(builder.Services, keyType, userType, roleType);
            RegisterBackgroundJobs(builder, keyType, userType, roleType);

            return builder;
        }

        /// <summary>
        /// Adds JWT bearer authentication and authorization, configured from
        /// <see cref="Options.AuthOptions.JWTOptions"/>.
        /// </summary>
        public static AuthDependencyBuilder AddJwtAuthentication(this AuthDependencyBuilder builder)
        {
            ArgumentNullException.ThrowIfNull(builder);

            var jwt = builder.Options.JWTOptions;

            builder.Services
                .AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = jwt.ValidateIssuer,
                        ValidateAudience = jwt.ValidateAudience,
                        ValidateLifetime = jwt.ValidateLifetime,
                        ValidateIssuerSigningKey = jwt.ValidateIssuerSigningKey,
                        ValidIssuer = jwt.Issuer,
                        ValidAudience = jwt.Audience,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.SigningKey)),
                        ClockSkew = jwt.ClockSkew
                    };
                });

            builder.Services.AddAuthorization();

            return builder;
        }

        /// <summary>
        /// Replaces the default <see cref="AuthErrorDescriber"/> with the supplied
        /// <typeparamref name="TDescriber"/>. Override any message-returning property to localize
        /// or customize the error messages produced by <c>AuthService</c>.
        /// </summary>
        public static AuthDependencyBuilder AddErrorDescriber<TDescriber>(this AuthDependencyBuilder builder)
            where TDescriber : AuthErrorDescriber
        {
            ArgumentNullException.ThrowIfNull(builder);

            builder.Services.AddScoped<AuthErrorDescriber, TDescriber>();
            return builder;
        }

        private static void RegisterDbContextAliases(
            IServiceCollection services,
            Type dbContextType,
            Type keyType,
            Type userType,
            Type roleType)
        {
            services.TryAddScoped(
                typeof(AuthDbContext<,,>).MakeGenericType(keyType, userType, roleType),
                sp => sp.GetRequiredService(dbContextType));
        }

        private static void RegisterAuthServices(
            IServiceCollection services,
            Type keyType,
            Type userType,
            Type roleType)
        {
            var authServiceType = typeof(AuthService<,,>).MakeGenericType(keyType, userType, roleType);

            services.TryAddScoped(typeof(IAuthService), authServiceType);
            services.TryAddScoped(typeof(IAuthService<>).MakeGenericType(userType), authServiceType);

            services.TryAddScoped(
                typeof(IRoleSeederService),
                typeof(RoleSeederService<,,>).MakeGenericType(keyType, userType, roleType));
        }

        private static void RegisterStores(
            IServiceCollection services,
            Type keyType,
            Type userType,
            Type roleType)
        {
            var roleStoreType = typeof(RoleStore<,,>).MakeGenericType(keyType, userType, roleType);
            services.TryAddScoped(roleStoreType);
            services.TryAddScoped(
                typeof(IRoleStore<>).MakeGenericType(roleType),
                sp => sp.GetRequiredService(roleStoreType));

            var userStoreType = typeof(UserStore<,,>).MakeGenericType(keyType, userType, roleType);
            services.TryAddScoped(userStoreType);
            services.TryAddScoped(
                typeof(IUserStore<>).MakeGenericType(userType),
                sp => sp.GetRequiredService(userStoreType));

            services.TryAddScoped(
                typeof(TokenStore<,,>).MakeGenericType(keyType, userType, roleType));
        }

        private static void RegisterBackgroundJobs(
            AuthDependencyBuilder builder,
            Type keyType,
            Type userType,
            Type roleType)
        {
            builder.Services.AddHostedService<RoleSeedingTask>();

            var cleanup = builder.Options.TokenCleanupOptions;
            if (cleanup?.Enabled != true)
                return;

            var cleanupServiceType = typeof(TokenCleanupTask<,,>)
                .MakeGenericType(keyType, userType, roleType);

            builder.Services.AddSingleton(cleanupServiceType, sp =>
                ActivatorUtilities.CreateInstance(
                    sp,
                    cleanupServiceType,
                    cleanup.CleanupInterval,
                    cleanup.RetentionPeriod));

            builder.Services.AddSingleton(sp =>
                (IHostedService)sp.GetRequiredService(cleanupServiceType));
        }

        private static (Type? TKey, Type TUser, Type? TRole)? ResolveAuthDbContextTypes(Type dbContextType)
        {
            for (var current = dbContextType; current is not null && current != typeof(object); current = current.BaseType)
            {
                if (!current.IsGenericType)
                    continue;

                var definition = current.GetGenericTypeDefinition();
                var args = current.GetGenericArguments();

                if (definition == typeof(AuthDbContext<>))
                    return (null, args[0], null);

                if (definition == typeof(AuthDbContext<,>))
                    return (args[0], args[1], null);

                if (definition == typeof(AuthDbContext<,,>))
                    return (args[0], args[1], args[2]);
            }

            return null;
        }
    }
}
