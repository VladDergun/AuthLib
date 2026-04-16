namespace AuthLib.Common.Builders
{
    public static class TOTPUrlBuilder
    {
        public static string Build(string key, string issuer, string accountName)
        {
            return $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(accountName)}?secret={Uri.EscapeDataString(key)}&issuer={Uri.EscapeDataString(issuer)}";
        }
    }
}
