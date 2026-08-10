using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WindowsGoodBye.Core;

/// <summary>
/// Minimal, dependency-free JWT (HS256) generation/validation used to authenticate the PC and
/// Android to the embedded relay. See docs/plan_push_auth_v2.md, section
/// "JWT para Autenticación al Relay".
///
/// Token shape (fixed — this is not a general-purpose JWT library):
/// <code>
/// Header:  { "alg": "HS256", "typ": "JWT" }
/// Payload: { "sub": device_id, "sid": session_id, "iat": unix_seconds, "exp": unix_seconds }
/// Signature: HMACSHA256(base64url(header) + "." + base64url(payload), signingKey)
/// </code>
/// The signing key is always a purpose-derived key (<see cref="RelayKeyDerivation.DeriveRelayKey"/>),
/// never the raw DeviceKey — see docs/plan_push_auth_v2.md decision #12.
/// </summary>
public static class JwtHelper
{
    private const string HeaderJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    private static readonly TimeSpan DefaultLifetime = TimeSpan.FromSeconds(60);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = null // we control property names explicitly via [JsonPropertyName]
    };

    /// <summary>
    /// Create and sign a JWT. <paramref name="subject"/> is the device_id (JWT "sub" claim),
    /// <paramref name="sessionId"/> is the push-auth session_id ("sid" claim).
    /// </summary>
    /// <param name="signingKey">
    /// The HMAC key — must be a purpose-derived key such as <see cref="RelayKeyDerivation.DeriveRelayKey"/>,
    /// never the raw DeviceKey.
    /// </param>
    /// <param name="lifetime">Token validity window. Defaults to 60 seconds per the plan.</param>
    public static string CreateToken(string subject, string sessionId, byte[] signingKey, TimeSpan? lifetime = null)
    {
        if (string.IsNullOrEmpty(subject)) throw new ArgumentException("subject required", nameof(subject));
        if (string.IsNullOrEmpty(sessionId)) throw new ArgumentException("sessionId required", nameof(sessionId));

        var now = DateTimeOffset.UtcNow;
        var exp = now.Add(lifetime ?? DefaultLifetime);

        var payload = new JwtPayload
        {
            Sub = subject,
            Sid = sessionId,
            Iat = now.ToUnixTimeSeconds(),
            Exp = exp.ToUnixTimeSeconds()
        };

        var headerSegment = Base64UrlEncode(Encoding.UTF8.GetBytes(HeaderJson));
        var payloadSegment = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions));
        var signingInput = $"{headerSegment}.{payloadSegment}";

        var signature = ComputeSignature(signingInput, signingKey);
        var signatureSegment = Base64UrlEncode(signature);

        return $"{signingInput}.{signatureSegment}";
    }

    /// <summary>
    /// Validate a JWT's signature, header and expiry. Returns true and populates
    /// <paramref name="payload"/> on success; otherwise returns false with a human-readable
    /// <paramref name="error"/> (safe to log — never reveals key material).
    /// </summary>
    /// <param name="token">The compact JWT string (header.payload.signature).</param>
    /// <param name="signingKey">The same purpose-derived key used to create the token.</param>
    /// <param name="payload">The decoded payload, if valid.</param>
    /// <param name="error">Failure reason, if invalid.</param>
    /// <param name="clockSkew">
    /// Extra leeway applied to the expiry check to tolerate minor clock drift between PC and phone.
    /// Defaults to zero — widen only after confirming real skew, per the plan's operational note on
    /// timestamp windows (widening blindly weakens the anti-replay-delay defense).
    /// </param>
    public static bool TryValidateToken(
        string token, byte[] signingKey, out JwtPayload? payload, out string? error, TimeSpan? clockSkew = null)
    {
        payload = null;
        error = null;

        if (string.IsNullOrEmpty(token))
        {
            error = "Token is empty";
            return false;
        }

        var parts = token.Split('.');
        if (parts.Length != 3)
        {
            error = "Malformed token (expected 3 segments)";
            return false;
        }

        var (headerSegment, payloadSegment, signatureSegment) = (parts[0], parts[1], parts[2]);

        byte[] headerBytes, payloadBytes, signatureBytes;
        try
        {
            headerBytes = Base64UrlDecode(headerSegment);
            payloadBytes = Base64UrlDecode(payloadSegment);
            signatureBytes = Base64UrlDecode(signatureSegment);
        }
        catch (FormatException)
        {
            error = "Malformed token (invalid base64url)";
            return false;
        }

        // Reject anything that isn't exactly the alg/typ we issue — prevents "alg confusion" /
        // downgrade attacks (e.g. an attacker-supplied "alg": "none").
        try
        {
            using var headerDoc = JsonDocument.Parse(headerBytes);
            var root = headerDoc.RootElement;
            var alg = root.TryGetProperty("alg", out var algEl) ? algEl.GetString() : null;
            var typ = root.TryGetProperty("typ", out var typEl) ? typEl.GetString() : null;
            if (alg != "HS256" || typ != "JWT")
            {
                error = "Unsupported or unexpected JWT header (alg/typ mismatch)";
                return false;
            }
        }
        catch (JsonException)
        {
            error = "Malformed token header";
            return false;
        }

        // Verify signature BEFORE trusting anything in the payload.
        var signingInput = $"{headerSegment}.{payloadSegment}";
        var expectedSignature = ComputeSignature(signingInput, signingKey);
        if (!CryptographicOperations.FixedTimeEquals(expectedSignature, signatureBytes))
        {
            error = "Signature verification failed";
            return false;
        }

        JwtPayload? decoded;
        try
        {
            decoded = JsonSerializer.Deserialize<JwtPayload>(payloadBytes, JsonOptions);
        }
        catch (JsonException)
        {
            error = "Malformed token payload";
            return false;
        }

        if (decoded == null || string.IsNullOrEmpty(decoded.Sub) || string.IsNullOrEmpty(decoded.Sid))
        {
            error = "Missing required claims (sub/sid)";
            return false;
        }

        var now = DateTimeOffset.UtcNow;
        var skew = clockSkew ?? TimeSpan.Zero;
        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(decoded.Exp);
        if (now > expiresAt.Add(skew))
        {
            error = "Token expired";
            return false;
        }

        payload = decoded;
        return true;
    }

    /// <summary>
    /// Read the "sub" (device_id) claim WITHOUT verifying the signature. Only safe to use to look up
    /// which device's key to load for the subsequent, mandatory <see cref="TryValidateToken"/> call —
    /// never trust the result of this method for authorization decisions.
    /// </summary>
    public static string? PeekSubjectUnsafe(string token)
    {
        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3) return null;

            var payloadBytes = Base64UrlDecode(parts[1]);
            using var doc = JsonDocument.Parse(payloadBytes);
            return doc.RootElement.TryGetProperty("sub", out var subEl) ? subEl.GetString() : null;
        }
        catch
        {
            return null;
        }
    }

    private static byte[] ComputeSignature(string signingInput, byte[] signingKey)
    {
        using var hmac = new HMACSHA256(signingKey);
        return hmac.ComputeHash(Encoding.UTF8.GetBytes(signingInput));
    }

    private static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
            case 0: break;
            default: throw new FormatException("Invalid base64url string length");
        }
        return Convert.FromBase64String(s);
    }
}

/// <summary>Decoded JWT payload for the fixed shape used by WindowsGoodBye's relay auth.</summary>
public sealed class JwtPayload
{
    /// <summary>Subject — the device_id of whoever generated the token (PC or Android device).</summary>
    [JsonPropertyName("sub")]
    public string Sub { get; set; } = "";

    /// <summary>Session ID this token is scoped to.</summary>
    [JsonPropertyName("sid")]
    public string Sid { get; set; } = "";

    /// <summary>Issued-at, Unix seconds (UTC).</summary>
    [JsonPropertyName("iat")]
    public long Iat { get; set; }

    /// <summary>Expiry, Unix seconds (UTC).</summary>
    [JsonPropertyName("exp")]
    public long Exp { get; set; }
}
