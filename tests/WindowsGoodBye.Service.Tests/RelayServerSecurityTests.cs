using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using WindowsGoodBye.Core;
using WindowsGoodBye.Service;
using Xunit;

namespace WindowsGoodBye.Service.Tests;

/// <summary>
/// Fase 13 (Testing &amp; Polish) — closes the remaining "Seguridad" gaps from
/// docs/plan_push_auth_v2.md's Fase 13 test table that <see cref="RelayServerTests"/> didn't already
/// cover:
/// <list type="bullet">
/// <item><description>"Relay: enviar body malformado/oversized a cada endpoint y verificar que el
/// proceso del Service no cae (solo 400/413/500 controlado)".</description></item>
/// <item><description>Replay of a captured/consumed <c>/respond</c> — distinct from the HMAC-timestamp
/// replay-delay window already covered by <see cref="AuthWorkerHmacVerificationTests"/> (that class
/// tests the pure timestamp-window math; this tests the RELAY's own session-lifecycle defense: once a
/// session is consumed/removed, the exact same captured request can never resolve it again).</description></item>
/// <item><description>The two rate-limit table rows <see cref="RelayServerTests"/> doesn't exercise:
/// the GLOBAL per-IP limiter (all endpoints) and the per-device <c>/api/device/token</c> limiter.</description></item>
/// <item><description>Double <c>/respond</c> for the same session (second call must not silently
/// "win" — a real relay could otherwise let an attacker race a second forged response against a
/// just-resolved session).</description></item>
/// </list>
/// Each test starts its own <see cref="RelayServer"/> on port 0, mirroring <see cref="RelayServerTests"/>.
/// </summary>
public class RelayServerSecurityTests : IAsyncLifetime
{
    private RelayServer _server = null!;
    private HttpClient _client = null!;

    private readonly Guid _deviceId = Guid.NewGuid();
    private readonly byte[] _deviceKey = RandomNumberGenerator.GetBytes(32);

    public async Task InitializeAsync()
    {
        byte[]? Resolve(string deviceIdString) =>
            deviceIdString == _deviceId.ToString() ? RelayKeyDerivation.DeriveRelayKey(_deviceKey) : null;

        _server = new RelayServer(NullLogger<RelayServer>.Instance, Resolve, port: 0);
        await _server.StartAsync();
        _client = new HttpClient { BaseAddress = new Uri($"http://localhost:{_server.BoundPort}") };
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _server.DisposeAsync();
    }

    private string MakeJwt(string sessionId) =>
        JwtHelper.CreateToken(_deviceId.ToString(), sessionId, RelayKeyDerivation.DeriveRelayKey(_deviceKey));

    /// <summary>After each malformed/oversized-body probe, confirm the relay is still alive and
    /// answering normally — the actual "did the process survive" check for an in-process Kestrel test
    /// host (there is no separate OS process to watch, so "still serving requests correctly" is the
    /// observable proxy for "didn't crash").</summary>
    private async Task AssertServerStillAliveAsync()
    {
        var health = await _client.GetAsync("/api/health");
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
    }

    // ---- Malformed body -----------------------------------------------------------------------

    public static IEnumerable<object[]> PostEndpoints => new List<object[]>
    {
        new object[] { "/api/auth/register" },
        new object[] { "/api/auth/respond" },
        new object[] { "/api/auth/reject" },
        new object[] { "/api/device/token" },
    };

    [Theory]
    [MemberData(nameof(PostEndpoints))]
    public async Task MalformedJsonBody_IsRejectedWithControlledStatus_ServerStaysUp(string path)
    {
        var content = new StringContent("{ this is not valid json !!", Encoding.UTF8, "application/json");
        var resp = await _client.PostAsync(path, content);

        // Malformed JSON means the JWT-extraction step in the pipeline can't find credentials at all,
        // so every endpoint uniformly reports 401 (missing_credentials) rather than reaching its own
        // per-DTO validation — still a controlled 4xx, never an unhandled exception/connection reset.
        Assert.True((int)resp.StatusCode is >= 400 and < 500,
            $"Expected a controlled 4xx for malformed JSON on {path}, got {(int)resp.StatusCode}");

        await AssertServerStillAliveAsync();
    }

    [Theory]
    [MemberData(nameof(PostEndpoints))]
    public async Task OversizedBody_IsRejectedWithControlledStatus_ServerStaysUp(string path)
    {
        // RelayLimits.MaxRequestBodyBytes is 16 KB — well past that, but still shaped like plausible
        // JSON so this exercises the body-size guard specifically, not just "any garbage".
        var oversizedField = new string('A', 32 * 1024);
        var body = $"{{\"session_id\":\"{oversizedField}\",\"device_id\":\"x\",\"expected_device_id\":\"x\",\"jwt\":\"y\",\"hmac\":\"z\",\"token\":\"t\",\"response_ts\":1}}";
        var content = new StringContent(body, Encoding.UTF8, "application/json");

        HttpResponseMessage resp;
        try
        {
            resp = await _client.PostAsync(path, content);
        }
        catch (HttpRequestException)
        {
            // Some Kestrel configurations reset the connection outright for a body that blows past
            // MaxRequestBodySize before any response can be written — that's still "handled" (no
            // process crash), just visible to the client as a connection failure rather than a status
            // code. Confirm the server is still alive afterward either way.
            await AssertServerStillAliveAsync();
            return;
        }

        Assert.True((int)resp.StatusCode is >= 400 and < 600,
            $"Expected a controlled 4xx/5xx for an oversized body on {path}, got {(int)resp.StatusCode}");

        await AssertServerStillAliveAsync();
    }

    // ---- Replay of a consumed /respond (relay-level, distinct from the HMAC timestamp window) ------

    [Fact]
    public async Task Respond_ReplayedAfterSessionAlreadyConsumedByWait_ReturnsNotFound()
    {
        var sessionId = Guid.NewGuid().ToString();
        var jwt = MakeJwt(sessionId);

        await _client.PostAsJsonAsync("/api/auth/register", new
        {
            session_id = sessionId,
            expected_device_id = _deviceId.ToString(),
            jwt
        });

        var waitRequest = new HttpRequestMessage(HttpMethod.Get, $"/api/auth/wait/{sessionId}");
        waitRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);
        var waitTask = _client.SendAsync(waitRequest);
        await Task.Delay(100);

        var capturedBody = new
        {
            session_id = sessionId,
            device_id = _deviceId.ToString(),
            hmac = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            response_ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            jwt
        };

        var firstRespond = await _client.PostAsJsonAsync("/api/auth/respond", capturedBody);
        Assert.Equal(HttpStatusCode.OK, firstRespond.StatusCode);

        var waitResp = await waitTask; // PC consumes the response -> AwaitEntryAsync removes the session
        Assert.Equal(HttpStatusCode.OK, waitResp.StatusCode);

        // An attacker who captured the exact same wire bytes (session_id, device_id, hmac,
        // response_ts, jwt — all still within their individual validity windows) replays them. The
        // session no longer exists, so the relay can't resolve anything with it — a distinct, relay-
        // level defense from AuthWorker's own >10s anti-replay-delay timestamp check.
        var replay = await _client.PostAsJsonAsync("/api/auth/respond", capturedBody);
        Assert.Equal(HttpStatusCode.NotFound, replay.StatusCode);
    }

    [Fact]
    public async Task Respond_CalledTwiceBeforeAnyoneWaits_SecondGetsConflict()
    {
        var sessionId = Guid.NewGuid().ToString();
        var jwt = MakeJwt(sessionId);

        await _client.PostAsJsonAsync("/api/auth/register", new
        {
            session_id = sessionId,
            expected_device_id = _deviceId.ToString(),
            jwt
        });

        Task<HttpResponseMessage> RespondOnceAsync(string hmacSeed) => _client.PostAsJsonAsync("/api/auth/respond", new
        {
            session_id = sessionId,
            device_id = _deviceId.ToString(),
            hmac = hmacSeed,
            response_ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            jwt
        });

        var first = await RespondOnceAsync(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        // Nobody called /wait yet, so the session is still in the dictionary — but the TaskCompletionSource
        // backing it was already resolved by the first /respond, so a second one (e.g. a race between a
        // legitimate response and a forged one) must not silently overwrite/re-resolve it.
        var second = await RespondOnceAsync(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    // ---- Rate limiting: the two table rows RelayServerTests doesn't already cover -----------------

    [Fact]
    public async Task GlobalPerIpRateLimit_Returns429_AcrossAnyEndpoint()
    {
        // "Global (todos los endpoints) | 100 req | por minuto, por IP | 429 Too Many Requests" — health
        // requires no JWT and is cheap, so it's used to drive the count without other limiters
        // (register's own 10/min policy) interfering.
        HttpResponseMessage? last429 = null;
        for (var i = 0; i < RelayLimits.GlobalPerMinutePerIp + 5; i++)
        {
            var resp = await _client.GetAsync("/api/health");
            if (resp.StatusCode == HttpStatusCode.TooManyRequests)
            {
                last429 = resp;
                break;
            }
        }

        Assert.NotNull(last429);
    }

    [Fact]
    public async Task DeviceTokenEndpoint_ExceedsPerDeviceRateLimit_Returns429()
    {
        // "POST /api/device/token | 5 req | por minuto, por device_id | 429 Too Many Requests"
        var jwt = MakeJwt("device-token-update"); // sid is irrelevant here — this endpoint doesn't bind to a session
        HttpResponseMessage? last429 = null;

        for (var i = 0; i < RelayLimits.DeviceTokenPerMinutePerDeviceId + 3; i++)
        {
            var resp = await _client.PostAsJsonAsync("/api/device/token", new
            {
                device_id = _deviceId.ToString(),
                token = $"fcm-token-{i}",
                jwt
            });

            if (resp.StatusCode == HttpStatusCode.TooManyRequests)
            {
                last429 = resp;
                break;
            }

            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        }

        Assert.NotNull(last429);
    }
}
