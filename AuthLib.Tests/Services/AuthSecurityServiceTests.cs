using AuthLib.Options;
using AuthLib.Services;
using AuthLib.Tests.Helpers;
using AwesomeAssertions;
using Microsoft.Extensions.Options;

namespace AuthLib.Tests.Services
{
    public class AuthSecurityServiceTests
    {
        private readonly AuthSecurityService _authSecurityService;
        private readonly IOptions<AuthOptions> _authOptions;

        public AuthSecurityServiceTests()
        {
            _authOptions = TestAuthOptionsFactory.Create();
            _authSecurityService = new AuthSecurityService(_authOptions);
        }

        #region Password Hashing Tests

        [Fact]
        public void HashPassword_ShouldReturnNonEmptyHash()
        {
            // Arrange
            var password = "TestPassword123";

            // Act
            var hash = _authSecurityService.HashPassword(password);

            // Assert
            hash.Should().NotBeNullOrEmpty();
            hash.Should().NotBe(password);
        }

        [Fact]
        public void HashPassword_ShouldReturnDifferentHashesForSamePassword()
        {
            // Arrange
            var password = "TestPassword123";

            // Act
            var hash1 = _authSecurityService.HashPassword(password);
            var hash2 = _authSecurityService.HashPassword(password);

            // Assert
            hash1.Should().NotBe(hash2); // BCrypt uses salt, so hashes differ
            hash1.Should().NotBeNullOrEmpty();
            hash2.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public void HashPassword_WithEmptyPassword_ShouldStillHash()
        {
            // Arrange
            var password = "";

            // Act
            var hash = _authSecurityService.HashPassword(password);

            // Assert
            hash.Should().NotBeNullOrEmpty();
        }

        #endregion

        #region Password Verification Tests

        [Fact]
        public void VerifyPassword_WithCorrectPassword_ShouldReturnTrue()
        {
            // Arrange
            var password = "TestPassword123";
            var hash = _authSecurityService.HashPassword(password);

            // Act
            var result = _authSecurityService.VerifyPassword(password, hash);

            // Assert
            result.Should().BeTrue();
        }

        [Fact]
        public void VerifyPassword_WithIncorrectPassword_ShouldReturnFalse()
        {
            // Arrange
            var password = "TestPassword123";
            var hash = _authSecurityService.HashPassword(password);

            // Act
            var result = _authSecurityService.VerifyPassword("WrongPassword", hash);

            // Assert
            result.Should().BeFalse();
        }

        [Fact]
        public void VerifyPassword_WithCaseSensitivePassword_ShouldBeCaseSensitive()
        {
            // Arrange
            var password = "TestPassword123";
            var hash = _authSecurityService.HashPassword(password);

            // Act
            var result = _authSecurityService.VerifyPassword("testpassword123", hash);

            // Assert
            result.Should().BeFalse();
        }

        [Fact]
        public void VerifyPassword_WithEmptyPassword_ShouldWork()
        {
            // Arrange
            var password = "";
            var hash = _authSecurityService.HashPassword(password);

            // Act
            var result = _authSecurityService.VerifyPassword(password, hash);

            // Assert
            result.Should().BeTrue();
        }

        #endregion

        #region Token Hashing Tests

        [Fact]
        public void HashToken_ShouldReturnConsistentHash()
        {
            // Arrange
            var token = "test-token-12345";

            // Act
            var hash1 = _authSecurityService.HashToken(token);
            var hash2 = _authSecurityService.HashToken(token);

            // Assert
            hash1.Should().Be(hash2); // Token hashing should be deterministic
            hash1.Should().NotBeNullOrEmpty();
        }

        [Fact]
        public void HashToken_WithDifferentTokens_ShouldReturnDifferentHashes()
        {
            // Arrange
            var token1 = "test-token-12345";
            var token2 = "test-token-67890";

            // Act
            var hash1 = _authSecurityService.HashToken(token1);
            var hash2 = _authSecurityService.HashToken(token2);

            // Assert
            hash1.Should().NotBe(hash2);
        }

        [Fact]
        public void HashToken_ShouldNotReturnOriginalToken()
        {
            // Arrange
            var token = "test-token-12345";

            // Act
            var hash = _authSecurityService.HashToken(token);

            // Assert
            hash.Should().NotBe(token);
        }

        #endregion

        #region Security Tests

        [Fact]
        public void HashPassword_ShouldUsePasswordSecret()
        {
            // Arrange
            var password = "TestPassword123";
            var options1 = TestAuthOptionsFactory.Create();
            var options2 = Microsoft.Extensions.Options.Options.Create(new AuthOptions
            {
                PasswordSecret = "different-secret",
                TokenSecret = options1.Value.TokenSecret,
                JWTOptions = options1.Value.JWTOptions,
                PasswordOptions = options1.Value.PasswordOptions,
                Roles = options1.Value.Roles
            });

            var service1 = new AuthSecurityService(options1);
            var service2 = new AuthSecurityService(options2);

            // Act
            var hash1 = service1.HashPassword(password);
            var hash2 = service2.HashPassword(password);

            // Assert - Different secrets should produce different hashes
            service2.VerifyPassword(password, hash1).Should().BeFalse();
            service1.VerifyPassword(password, hash2).Should().BeFalse();
        }

        [Fact]
        public void HashToken_ShouldUseTokenSecret()
        {
            // Arrange
            var token = "test-token";
            var options1 = TestAuthOptionsFactory.Create();
            var options2 = Microsoft.Extensions.Options.Options.Create(new AuthOptions
            {
                PasswordSecret = options1.Value.PasswordSecret,
                TokenSecret = "different-token-secret",
                JWTOptions = options1.Value.JWTOptions,
                PasswordOptions = options1.Value.PasswordOptions,
                Roles = options1.Value.Roles
            });

            var service1 = new AuthSecurityService(options1);
            var service2 = new AuthSecurityService(options2);

            // Act
            var hash1 = service1.HashToken(token);
            var hash2 = service2.HashToken(token);

            // Assert - Different secrets should produce different hashes
            hash1.Should().NotBe(hash2);
        }

        #endregion
    }
}
