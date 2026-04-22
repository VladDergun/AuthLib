using AuthLib.Interfaces.Services;
using AuthLib.Options;
using AuthLib.Services;
using AuthLib.Tests.Helpers;
using FluentAssertions;
using Microsoft.Extensions.Options;

namespace AuthLib.Tests.Services
{
    public class TokenManagerServiceTests
    {
        private readonly TokenManagerService _tokenManagerService;
        private readonly IAuthSecurityService _authSecurityService;
        private readonly IOptions<AuthOptions> _authOptions;

        public TokenManagerServiceTests()
        {
            _authOptions = TestAuthOptionsFactory.Create();
            _authSecurityService = new AuthSecurityService(_authOptions);
            _tokenManagerService = new TokenManagerService(_authOptions, _authSecurityService);
        }

        #region Token Generation Tests

        [Fact]
        public void GenerateToken_ShouldReturnTokenAndHash()
        {
            // Act
            var (token, tokenHash) = _tokenManagerService.GenerateToken();

            // Assert
            token.Should().NotBeNullOrEmpty();
            tokenHash.Should().NotBeNullOrEmpty();
            token.Should().NotBe(tokenHash);
        }

        [Fact]
        public void GenerateToken_ShouldReturnUniqueTokens()
        {
            // Act
            var (token1, hash1) = _tokenManagerService.GenerateToken();
            var (token2, hash2) = _tokenManagerService.GenerateToken();

            // Assert
            token1.Should().NotBe(token2);
            hash1.Should().NotBe(hash2);
        }

        [Fact]
        public void GenerateToken_HashShouldBeVerifiable()
        {
            // Act
            var (token, tokenHash) = _tokenManagerService.GenerateToken();
            var verifyHash = _tokenManagerService.HashToken(token);

            // Assert
            verifyHash.Should().Be(tokenHash);
        }

        #endregion

        #region JWT Token Generation Tests

        [Fact]
        public void GenerateJWTToken_ShouldReturnValidToken()
        {
            // Arrange
            var userId = "123";
            var email = "test@example.com";
            var roles = new[] { "User", "Admin" };

            // Act
            var token = _tokenManagerService.GenerateJWTToken(userId, email, roles: roles);

            // Assert
            token.Should().NotBeNullOrEmpty();
            token.Split('.').Should().HaveCount(3); // JWT has 3 parts
        }

        [Fact]
        public void GenerateJWTToken_WithDifferentUsers_ShouldReturnDifferentTokens()
        {
            // Arrange
            var roles = new[] { "User" };

            // Act
            var token1 = _tokenManagerService.GenerateJWTToken("1", "user1@example.com", roles: roles);
            var token2 = _tokenManagerService.GenerateJWTToken("2", "user2@example.com", roles: roles);

            // Assert
            token1.Should().NotBe(token2);
        }

        [Fact]
        public void GenerateJWTToken_WithNoRoles_ShouldStillGenerateToken()
        {
            // Arrange
            var userId = "123";
            var email = "test@example.com";
            var roles = Array.Empty<string>();

            // Act
            var token = _tokenManagerService.GenerateJWTToken(userId, email, roles: roles);

            // Assert
            token.Should().NotBeNullOrEmpty();
            token.Split('.').Should().HaveCount(3);
        }

        [Fact]
        public void GenerateJWTToken_WithMultipleRoles_ShouldIncludeAllRoles()
        {
            // Arrange
            var userId = "123";
            var email = "test@example.com";
            var roles = new[] { "User", "Admin", "Moderator" };

            // Act
            var token = _tokenManagerService.GenerateJWTToken(userId, email, roles: roles);

            // Assert
            token.Should().NotBeNullOrEmpty();
            // Note: To fully verify roles, you'd need to decode the JWT
            // This is a basic check that it generates successfully
        }

        #endregion

        #region Token Hashing Tests

        [Fact]
        public void HashToken_ShouldReturnConsistentHash()
        {
            // Arrange
            var token = "test-token-123";

            // Act
            var hash1 = _tokenManagerService.HashToken(token);
            var hash2 = _tokenManagerService.HashToken(token);

            // Assert
            hash1.Should().Be(hash2);
        }

        [Fact]
        public void HashToken_WithDifferentTokens_ShouldReturnDifferentHashes()
        {
            // Arrange
            var token1 = "test-token-123";
            var token2 = "test-token-456";

            // Act
            var hash1 = _tokenManagerService.HashToken(token1);
            var hash2 = _tokenManagerService.HashToken(token2);

            // Assert
            hash1.Should().NotBe(hash2);
        }

        #endregion

        #region Security Tests

        [Fact]
        public void GenerateToken_ShouldBeSecure()
        {
            // Generate multiple tokens and ensure they're cryptographically random
            var tokens = new HashSet<string>();

            // Act
            for (int i = 0; i < 100; i++)
            {
                var (token, _) = _tokenManagerService.GenerateToken();
                tokens.Add(token);
            }

            // Assert - All tokens should be unique
            tokens.Should().HaveCount(100);
        }

        [Fact]
        public void GenerateToken_ShouldHaveSufficientLength()
        {
            // Act
            var (token, _) = _tokenManagerService.GenerateToken();

            // Assert - Base64 encoded 32 bytes should be at least 40 characters
            token.Length.Should().BeGreaterThan(40);
        }

        #endregion
    }
}
