using AuthLib.Models;
using AuthLib.Options;
using AuthLib.Services;
using AuthLib.Services.Stores;
using AuthLib.Tests.Helpers;
using FluentAssertions;
using Microsoft.EntityFrameworkCore;

namespace AuthLib.Tests.Services
{
    public class RoleManagerServiceTests : IClassFixture<PostgreSqlContainerFixture>, IAsyncLifetime
    {
        private readonly PostgreSqlContainerFixture _fixture;
        private TestDbContext _dbContext = null!;
        private RoleSeederService<int, TestUser, AuthRole<int>> _roleManagerService = null!;
        private RoleStore<int, TestUser, AuthRole<int>> _roleStore = null!;

        public RoleManagerServiceTests(PostgreSqlContainerFixture fixture)
        {
            _fixture = fixture;
        }

        public async ValueTask InitializeAsync()
        {
            _dbContext = TestDbContextFactory.CreateContext(_fixture.ConnectionString);
            _roleStore = new RoleStore<int, TestUser, AuthRole<int>>(_dbContext);
            _roleManagerService = new RoleSeederService<int, TestUser, AuthRole<int>>(_roleStore);
        }

        public async ValueTask DisposeAsync()
        {
            await _dbContext.Database.EnsureDeletedAsync();
            await _dbContext.DisposeAsync();
        }

        #region Role Seeding Tests

        [Fact]
        public async Task SeedRolesAsync_ShouldCreateRoles()
        {
            // Arrange
            var roles = new List<Role>
            {
                new() { Name = "User", IsDefault = true },
                new() { Name = "Admin", IsDefault = false }
            };

            // Act
            await _roleManagerService.SeedRolesAsync(roles, CancellationToken.None);

            // Assert
            var dbRoles = await _dbContext.AuthRoles.ToListAsync(TestContext.Current.CancellationToken);
            dbRoles.Should().HaveCount(2);
            dbRoles.Should().Contain(r => r.Name == "User");
            dbRoles.Should().Contain(r => r.Name == "Admin");
        }

        [Fact]
        public async Task SeedRolesAsync_ShouldSetDefaultRole()
        {
            // Arrange
            var roles = new List<Role>
            {
                new() { Name = "User", IsDefault = true },
                new() { Name = "Admin", IsDefault = false }
            };

            // Act
            await _roleManagerService.SeedRolesAsync(roles, TestContext.Current.CancellationToken);

            // Assert
            var defaultRole = await _dbContext.AuthRoles.FirstOrDefaultAsync(r => r.IsDefault, TestContext.Current.CancellationToken);
            defaultRole.Should().NotBeNull();
            defaultRole!.Name.Should().Be("User");
        }

        [Fact]
        public async Task SeedRolesAsync_ShouldNotDuplicateExistingRoles()
        {
            // Arrange
            var roles = new List<Role>
            {
                new() { Name = "User", IsDefault = true }
            };

            // Act - Seed twice
            await _roleManagerService.SeedRolesAsync(roles, TestContext.Current.CancellationToken);
            await _roleManagerService.SeedRolesAsync(roles, TestContext.Current.CancellationToken);

            // Assert
            var dbRoles = await _dbContext.AuthRoles.ToListAsync(TestContext.Current.CancellationToken);
            dbRoles.Should().HaveCount(1);
        }

        [Fact]
        public async Task SeedRolesAsync_ShouldDeactivateRemovedRoles()
        {
            // Arrange
            var initialRoles = new List<Role>
            {
                new() { Name = "User", IsDefault = true },
                new() { Name = "Admin", IsDefault = false },
                new() { Name = "Moderator", IsDefault = false }
            };

            await _roleManagerService.SeedRolesAsync(initialRoles, TestContext.Current.CancellationToken);

            var updatedRoles = new List<Role>
            {
                new() { Name = "User", IsDefault = true },
                new() { Name = "Admin", IsDefault = false }
            };

            // Act
            await _roleManagerService.SeedRolesAsync(updatedRoles, TestContext.Current.CancellationToken);

            // Assert
            var moderatorRole = await _dbContext.AuthRoles.FirstOrDefaultAsync(r => r.Name == "Moderator", TestContext.Current.CancellationToken);
            moderatorRole.Should().NotBeNull();
            moderatorRole!.IsActive.Should().BeFalse();
        }

        [Fact]
        public async Task SeedRolesAsync_ShouldChangeDefaultRole()
        {
            // Arrange
            var initialRoles = new List<Role>
            {
                new() { Name = "User", IsDefault = true },
                new() { Name = "Admin", IsDefault = false }
            };

            await _roleManagerService.SeedRolesAsync(initialRoles, TestContext.Current.CancellationToken);

            var updatedRoles = new List<Role>
            {
                new() { Name = "User", IsDefault = false },
                new() { Name = "Admin", IsDefault = true }
            };

            // Act
            await _roleManagerService.SeedRolesAsync(updatedRoles, TestContext.Current.CancellationToken);

            // Assert
            var userRole = await _dbContext.AuthRoles.FirstAsync(r => r.Name == "User", TestContext.Current.CancellationToken);
            var adminRole = await _dbContext.AuthRoles.FirstAsync(r => r.Name == "Admin", TestContext.Current.CancellationToken);

            userRole.IsDefault.Should().BeFalse();
            adminRole.IsDefault.Should().BeTrue();
        }

        [Fact]
        public async Task SeedRolesAsync_ShouldOnlyHaveOneDefaultRole()
        {
            // Arrange
            var roles = new List<Role>
            {
                new() { Name = "User", IsDefault = true },
                new() { Name = "Admin", IsDefault = false },
                new() { Name = "Moderator", IsDefault = false }
            };

            // Act
            await _roleManagerService.SeedRolesAsync(roles, TestContext.Current.CancellationToken);

            // Assert
            var defaultRoles = await _dbContext.AuthRoles.Where(r => r.IsDefault).ToListAsync(TestContext.Current.CancellationToken);
            defaultRoles.Should().HaveCount(1);
        }

        #endregion

        #region Role Store Tests

        [Fact]
        public async Task RoleStore_ShouldCacheRoles()
        {
            // Arrange
            var roles = new List<Role>
            {
                new() { Name = "User", IsDefault = true },
                new() { Name = "Admin", IsDefault = false }
            };

            await _roleManagerService.SeedRolesAsync(roles, TestContext.Current.CancellationToken);

            // Act
            var defaultRole = await _roleStore.GetDefaultAsync(TestContext.Current.CancellationToken);
            var adminRole = await _roleStore.GetByNameAsync("Admin", TestContext.Current.CancellationToken);

            // Assert
            defaultRole.Should().NotBeNull();
            defaultRole.Name.Should().Be("User");
            adminRole.Should().NotBeNull();
            adminRole.Name.Should().Be("Admin");
        }

        [Fact]
        public async Task RoleStore_GetRoleByName_ShouldBeCaseInsensitive()
        {
            // Arrange
            var roles = new List<Role>
            {
                new() { Name = "User", IsDefault = true }
            };

            await _roleManagerService.SeedRolesAsync(roles, TestContext.Current.CancellationToken);

            // Act
            var role = await _roleStore.GetByNameAsync("user", TestContext.Current.CancellationToken);

            // Assert
            role.Should().NotBeNull();
            role.Name.Should().Be("User");
        }

        #endregion
    }
}
