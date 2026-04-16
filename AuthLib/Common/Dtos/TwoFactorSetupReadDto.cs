namespace AuthLib.Common.Dtos
{
    public record TwoFactorSetupReadDto(string JWTToken, string QRCodeUri);
}
