using AuthLib.Enums;

namespace AuthLib.Common.Dtos
{
    public record TokenReadDto(string? AccessToken, string Token, TokenType TokenType, string? UserId = null);
}
