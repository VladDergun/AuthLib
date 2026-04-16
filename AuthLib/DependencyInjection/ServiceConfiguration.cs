using AuthLib.Contexts;
using AuthLib.Interfaces;
using AuthLib.Interfaces.Services;
using AuthLib.Models;
using AuthLib.Options;
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
    public static class ServiceConfiguration
    {
        public static AuthDependencyBuilder AddAuthServices(
           this IServiceCollection services,
           AuthOptions options)
        {
            services.Configure<AuthOptions>(opts =>
            {
                opts.PasswordSecret = options.PasswordSecret;
                opts.TokenSecret = options.TokenSecret;
                opts.Roles = options.Roles;
                opts.JWTOptions = options.JWTOptions;
                opts.PasswordOptions = options.PasswordOptions;
                opts.TokenCleanupOptions = options.TokenCleanupOptions;
                opts.EmailVerificationRequired = options.EmailVerificationRequired;
                opts.TwoFactorAuthOptions = options.TwoFactorAuthOptions;
            });

            services.AddScoped<IAuthSecurityService, AuthSecurityService>();
            services.AddScoped<ITokenManagerService, TokenManagerService>();

            return new AuthDependencyBuilder
            {
                Services = services,
                Options = options
            };
        }

        public static AuthDependencyBuilder AddEntityFrameworkStores<TDbContext>(
            this AuthDependencyBuilder authDependencyBuilder)
            where TDbContext : DbContext, IAuthDbContext
        {
            var types = GetAuthDbContextTypes(typeof(TDbContext));

            if (types == null)
                throw new InvalidOperationException(
                    $"{typeof(TDbContext).Name} must inherit from AuthDbContext<TKey, TUser, TRole>");

            var (keyType, userType, roleType) = types.Value;

            keyType ??= typeof(string);
            roleType ??= typeof(AuthRole<>).MakeGenericType(keyType);

            var dbContextType = typeof(TDbContext);

            authDependencyBuilder.Services.TryAddScoped(
                typeof(AuthDbContext<,,>).MakeGenericType(keyType, userType, roleType),
                sp => sp.GetRequiredService(dbContextType)
            );

            var authServiceType = typeof(AuthService<,,>)
                .MakeGenericType(keyType, userType, roleType);

            authDependencyBuilder.Services.TryAddScoped(typeof(IAuthService), authServiceType);
            authDependencyBuilder.Services.TryAddScoped(
                typeof(IAuthService<>).MakeGenericType(userType),
                authServiceType);

            authDependencyBuilder.Services.TryAddScoped(typeof(IRoleSeederService), typeof(RoleSeederService<,,>)
                .MakeGenericType(keyType, userType, roleType));

            authDependencyBuilder.Services.TryAddScoped(typeof(RoleStore<,,>)
                .MakeGenericType(keyType, userType, roleType));

            var userStoreType = typeof(UserStore<,,>)
                .MakeGenericType(keyType, userType, roleType);

            authDependencyBuilder.Services.TryAddScoped(userStoreType);
            authDependencyBuilder.Services.TryAddScoped(
                typeof(IUserStore<>).MakeGenericType(userType),
                sp => sp.GetRequiredService(userStoreType));

            authDependencyBuilder.Services.TryAddScoped(typeof(TokenStore<,,>)
                .MakeGenericType(keyType, userType, roleType));


            authDependencyBuilder.Services.AddHostedService<RoleSeedingTask>();

            if (authDependencyBuilder.Options.TokenCleanupOptions?.Enabled == true)
            {
                var cleanupServiceType = typeof(TokenCleanupTask<,,>)
                    .MakeGenericType(keyType, userType, roleType);

                authDependencyBuilder.Services.AddSingleton(cleanupServiceType, sp =>
                {
                    return ActivatorUtilities.CreateInstance(
                        sp,
                        cleanupServiceType,
                        authDependencyBuilder.Options.TokenCleanupOptions.CleanupInterval,
                        authDependencyBuilder.Options.TokenCleanupOptions.RetentionPeriod);
                });

                authDependencyBuilder.Services.AddSingleton(sp =>
                    (IHostedService)sp.GetRequiredService(cleanupServiceType));
            }

            return authDependencyBuilder;
        }

        public static AuthDependencyBuilder AddJwtAuthentication(this AuthDependencyBuilder authDependencyBuilder)
        {
            var jwtOptions = authDependencyBuilder.Options.JWTOptions;

            authDependencyBuilder.Services
                .AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = jwtOptions.Issuer,
                        ValidAudience = jwtOptions.Audience,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.SigningKey)),
                        ClockSkew = TimeSpan.Zero
                    };
                });

            authDependencyBuilder.Services.AddAuthorization();

            return authDependencyBuilder;
        }

        private static (Type? TKey, Type TUser, Type? TRole)? GetAuthDbContextTypes(Type dbContextType)
        {
            var current = dbContextType;

            while (current != null && current != typeof(object))
            {
                if (current.IsGenericType &&
                    current.GetGenericTypeDefinition() == typeof(AuthDbContext<>))
                {
                    var args = current.GetGenericArguments();
                    return (null, args[0], null);
                }
                else if (current.IsGenericType &&
                    current.GetGenericTypeDefinition() == typeof(AuthDbContext<,>))
                {
                    var args = current.GetGenericArguments();
                    return (args[0], args[1], null);
                }
                else if (current.IsGenericType &&
                    current.GetGenericTypeDefinition() == typeof(AuthDbContext<,,>))
                {
                    var args = current.GetGenericArguments();
                    return (args[0], args[1], args[2]);
                }

                current = current.BaseType!;
            }

            return null;
        }
    }

}
