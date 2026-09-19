using System.Security.Cryptography;
using System.Text;

namespace CklMcp.Http;

/// <summary>
/// Checks the <c>Authorization: Bearer</c> header against the configured token. Both sides are hashed
/// first and compared in constant time, so neither the token's length nor how much of it matched
/// can be learned from response timing.
/// </summary>
public sealed class TokenAuthenticator
{
    private const string Scheme = "Bearer ";
    private readonly byte[] _expected;

    public TokenAuthenticator(string token) =>
        _expected = SHA256.HashData(Encoding.UTF8.GetBytes(token));

    public bool IsAuthorized(string? authorizationHeader)
    {
        if (string.IsNullOrEmpty(authorizationHeader) ||
            !authorizationHeader.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var presented = authorizationHeader.AsSpan(Scheme.Length).Trim().ToString();
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(presented));
        return CryptographicOperations.FixedTimeEquals(hash, _expected);
    }
}
