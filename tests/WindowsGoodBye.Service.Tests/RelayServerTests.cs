using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using WindowsGoodBye.Core;
using WindowsGoodBye.Service;
using Xunit;

namespace WindowsGoodBye.Service.Tests;

/// <summary>
/// Smoke/integration tests for the embedded push-auth <see cref="RelayServer"/> (Fase 2). Exercises
/// the real Kestrel pipeline end-to-end over loopback HTTP (never a real network) — JWT validation,
/// register → wait → respond/reject, session-device binding (Fisura #7), and the rate-limiting table
/// from docs/plan_push_auth_v2.md ("🛡️ Rate Limiting en el Relay").
///
/// Each test starts its own <see cref="RelayServer"/> on port 0 (OS-assigned free port) so tests can
/// run in parallel/without colliding with a real Service instance using <see cref="Protocol.RelayPort"/>.
/// </summary>
public class RelayServerTests : IAsyncLifetime
{
    private RelayServer _server = null!;
    private HttpClient _client = null!;

    // A single "known" device used by most tests.
    private readonly Guid _deviceId = Guid.NewGuid();
    private readonly byte[] _deviceKey = RandomNumberGenerator.GetBytes(32);
    private byte[] RelayKey => RelayKeyDerivation.DeriveRelayKey(_deviceKey);

    // A second, independently-keyed device, used for the session-device-binding (Fisura #7) test.
    private readonly Guid _otherDeviceId = Guid.NewGuid();
    private readonly byte[] _otherDeviceKey = RandomNumberGenerator.GetBytes(32);

    public async Task InitializeAsync()
    {
        byte[]? Resolve(string deviceIdString)
        {
            if (deviceIdString == _deviceId.ToString()) return RelayKeyDerivation.DeriveRelayKey(_deviceKey);
            if (deviceIdString == _otherDeviceId.ToString()) return RelayKeyDerivation.DeriveRelayKey(_otherDeviceKey);
            return null;
        }

        _server = new RelayServer(NullLogger<RelayServer>.Instance, Resolve, port: 0);
        await _server.StartAsync();

        _client = new HttpClient { BaseAddress = new Uri($"http://localhost:{_server.BoundPort}") };
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _server.DisposeAsync();
    }

    private string MakeJwt(Guid deviceId, byte[] deviceKey, string sessionId) =>
        JwtHelper.CreateToken(deviceId.ToString(), sessionId, RelayKeyDerivation.DeriveRelayKey(deviceKey));

    [Fact]
    public async Task Health_DoesNotRequireJwt()
    {
        var resp = await _client.GetAsync("/api/health");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Register_MissingJwt_Returns401()
    {
        var resp = await _client.PostAsJsonAsync("/api/auth/register", new
        {
            session_id = Guid.NewGuid().ToString(),
            expected_device_id = _deviceId.ToString(),
            jwt = "" // deliberately missing
        });

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Register_UnknownDevice_Returns401()
    {
        var sessionId = Guid.NewGuid().ToString();
        var unknownDeviceId = Guid.NewGuid();
        var unknownKey = RandomNumberGenerator.GetBytes(32);
        var jwt = MakeJwt(unknownDeviceId, unknownKey, sessionId);

        var resp = await _client.PostAsJsonAsync("/api/auth/register", new
        {
            session_id = sessionId,
            expected_device_id = unknownDeviceId.ToString(),
            jwt
        });

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task RegisterWaitRespond_FullHappyPath_Succeeds()
    {
        var sessionId = Guid.NewGuid().ToString();
        var jwt = MakeJwt(_deviceId, _deviceKey, sessionId);

        var registerResp = await _client.PostAsJsonAsync("/api/auth/register", new
        {
            session_id = sessionId,
            expected_device_id = _deviceId.ToString(),
            jwt
        });
        Assert.Equal(HttpStatusCode.OK, registerResp.StatusCode);

        // PC starts long-polling /wait concurrently with Android's /respond.
        var waitRequest = new HttpRequestMessage(HttpMethod.Get, $"/api/auth/wait/{sessionId}");
        waitRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);
        var waitTask = _client.SendAsync(waitRequest);

        // Give the wait a moment to actually start polling before Android responds.
        await Task.Delay(100);

        var responseTs = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var respondResp = await _client.PostAsJsonAsync("/api/auth/respond", new
        {
            session_id = sessionId,
            device_id = _deviceId.ToString(),
            hmac = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            response_ts = responseTs,
            jwt
        });
        Assert.Equal(HttpStatusCode.OK, respondResp.StatusCode);

        var waitResp = await waitTask;
        Assert.Equal(HttpStatusCode.OK, waitResp.StatusCode);

        using var doc = JsonDocument.Parse(await waitResp.Content.ReadAsStringAsync());
        Assert.Equal("ok", doc.RootElement.GetProperty("status").GetString());
        Assert.Equal(_deviceId.ToString(), doc.RootElement.GetProperty("device_id").GetString());
        Assert.Equal(responseTs, doc.RootElement.GetProperty("response_ts").GetInt64());
    }

    [Fact]
    public async Task Respond_WithWrongDeviceId_Returns403_SessionDeviceBinding()
    {
        // Session is registered expecting _deviceId, but the responder is _otherDeviceId (its own
        // valid JWT, just not the device this session is bound to) — Fisura #7.
        var sessionId = Guid.NewGuid().ToString();
        var registerJwt = MakeJwt(_deviceId, _deviceKey, sessionId);

        var registerResp = await _client.PostAsJsonAsync("/api/auth/register", new
        {
            session_id = sessionId,
            expected_device_id = _deviceId.ToString(),
            jwt = registerJwt
        });
        Assert.Equal(HttpStatusCode.OK, registerResp.StatusCode);

        var otherJwt = MakeJwt(_otherDeviceId, _otherDeviceKey, sessionId);
        var respondResp = await _client.PostAsJsonAsync("/api/auth/respond", new
        {
            session_id = sessionId,
            device_id = _otherDeviceId.ToString(),
            hmac = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            response_ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            jwt = otherJwt
        });

        Assert.Equal(HttpStatusCode.Forbidden, respondResp.StatusCode);
    }

    [Fact]
    public async Task Reject_MarksSessionRejected_DistinctFromTimeout()
    {
        var sessionId = Guid.NewGuid().ToString();
        var jwt = MakeJwt(_deviceId, _deviceKey, sessionId);

        var registerResp = await _client.PostAsJsonAsync("/api/auth/register", new
        {
            session_id = sessionId,
            expected_device_id = _deviceId.ToString(),
            jwt
        });
        Assert.Equal(HttpStatusCode.OK, registerResp.StatusCode);

        var waitRequest = new HttpRequestMessage(HttpMethod.Get, $"/api/auth/wait/{sessionId}");
        waitRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);
        var waitTask = _client.SendAsync(waitRequest);

        await Task.Delay(100);

        var rejectResp = await _client.PostAsJsonAsync("/api/auth/reject", new
        {
            session_id = sessionId,
            device_id = _deviceId.ToString(),
            reason = "not_my_pc",
            jwt
        });
        Assert.Equal(HttpStatusCode.OK, rejectResp.StatusCode);

        var waitResp = await waitTask;
        Assert.Equal(HttpStatusCode.OK, waitResp.StatusCode); // rejection is a legitimate outcome, not an HTTP error
        using var doc = JsonDocument.Parse(await waitResp.Content.ReadAsStringAsync());
        Assert.Equal("rejected", doc.RootElement.GetProperty("status").GetString());
        Assert.Equal("not_my_pc", doc.RootElement.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task Wait_UnknownSession_Returns408Expired()
    {
        var sessionId = Guid.NewGuid().ToString();
        var jwt = MakeJwt(_deviceId, _deviceKey, sessionId); // valid JWT, but nothing was ever registered

        var waitRequest = new HttpRequestMessage(HttpMethod.Get, $"/api/auth/wait/{sessionId}");
        waitRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);
        var resp = await _client.SendAsync(waitRequest);

        Assert.Equal(HttpStatusCode.RequestTimeout, resp.StatusCode);
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        Assert.Equal("expired", doc.RootElement.GetProperty("status").GetString());
    }

    [Fact]
    public async Task Wait_ConcurrentPollsOnSameSession_SecondGets409()
    {
        var sessionId = Guid.NewGuid().ToString();
        var jwt = MakeJwt(_deviceId, _deviceKey, sessionId);

        await _client.PostAsJsonAsync("/api/auth/register", new
        {
            session_id = sessionId,
            expected_device_id = _deviceId.ToString(),
            jwt
        });

        HttpRequestMessage NewWaitRequest()
        {
            var req = new HttpRequestMessage(HttpMethod.Get, $"/api/auth/wait/{sessionId}");
            req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);
            return req;
        }

        var firstWaitTask = _client.SendAsync(NewWaitRequest());
        await Task.Delay(100); // let the first /wait actually start polling

        var secondResp = await _client.SendAsync(NewWaitRequest());
        Assert.Equal(HttpStatusCode.Conflict, secondResp.StatusCode);

        // Clean up the still-pending first wait by rejecting the session.
        await _client.PostAsJsonAsync("/api/auth/reject", new
        {
            session_id = sessionId,
            device_id = _deviceId.ToString(),
            jwt
        });
        await firstWaitTask;
    }

    [Fact]
    public async Task Register_ExceedsPerIpRateLimit_Returns429()
    {
        // "POST /api/auth/register | 10 req | por minuto, por IP | 429 Too Many Requests"
        HttpResponseMessage? last429 = null;
        for (var i = 0; i < RelayLimits.RegisterPerMinutePerIp + 2; i++)
        {
            var sessionId = Guid.NewGuid().ToString();
            var jwt = MakeJwt(_deviceId, _deviceKey, sessionId);
            var resp = await _client.PostAsJsonAsync("/api/auth/register", new
            {
                session_id = sessionId,
                expected_device_id = _deviceId.ToString(),
                jwt
            });

            if (resp.StatusCode == HttpStatusCode.TooManyRequests)
            {
                last429 = resp;
                break;
            }
        }

        Assert.NotNull(last429);
    }

    [Fact]
    public async Task Respond_ExceedsAttemptLimit_InvalidatesSession()
    {
        // "POST /api/auth/respond | 5 intentos | por session_id | 403 Forbidden + invalida la sesión"
        var sessionId = Guid.NewGuid().ToString();
        var registerJwt = MakeJwt(_deviceId, _deviceKey, sessionId);
        await _client.PostAsJsonAsync("/api/auth/register", new
        {
            session_id = sessionId,
            expected_device_id = _deviceId.ToString(),
            jwt = registerJwt
        });

        // Every attempt uses the WRONG device_id so none of them ever succeed and consume the session
        // via TrySetResult — this isolates the attempt-counter behavior from the happy path.
        var otherJwt = MakeJwt(_otherDeviceId, _otherDeviceKey, sessionId);
        HttpResponseMessage last = null!;
        for (var i = 0; i < RelayLimits.MaxRespondAttemptsPerSession + 1; i++)
        {
            last = await _client.PostAsJsonAsync("/api/auth/respond", new
            {
                session_id = sessionId,
                device_id = _otherDeviceId.ToString(),
                hmac = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                response_ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                jwt = otherJwt
            });
        }

        Assert.Equal(HttpStatusCode.Forbidden, last.StatusCode);
        using var doc = JsonDocument.Parse(await last.Content.ReadAsStringAsync());
        Assert.Equal("too_many_attempts", doc.RootElement.GetProperty("error").GetString());
    }

    /// <summary>
    /// Fase 8 smoke test — "🖥️ Múltiples PCs Emparejadas": two independent push-auth sessions for the
    /// SAME phone (two different paired PCs racing Ruta C simultaneously) must resolve completely
    /// independently by session_id. Uses the in-process API (RegisterSessionDirect/
    /// WaitForResponseDirectAsync), the same surface AuthWorker.TryPushAuthAsync actually uses in
    /// production, rather than the HTTP surface the other tests in this file exercise.
    /// </summary>
    [Fact]
    public async Task TwoIndependentSessions_ResolveIndependently_MultiPc()
    {
        var sessionA = Guid.NewGuid().ToString("n");
        var sessionB = Guid.NewGuid().ToString("n");

        // Same phone (_deviceId) receiving challenges from two different PCs "at once" — each PC only
        // knows its own session_id, so from the relay's point of view these are just two unrelated
        // pending sessions that happen to share a device_id.
        _server.RegisterSessionDirect(sessionA, _deviceId, nonce: RandomNumberGenerator.GetBytes(32), displayCode: "11", attemptNumber: 1);
        _server.RegisterSessionDirect(sessionB, _deviceId, nonce: RandomNumberGenerator.GetBytes(32), displayCode: "22", attemptNumber: 1);

        var waitA = _server.WaitForResponseDirectAsync(sessionA, CancellationToken.None);
        var waitB = _server.WaitForResponseDirectAsync(sessionB, CancellationToken.None);

        // Reject session A ("No es mi PC" on PC #1's challenge) — session B must be completely unaffected.
        var rejectJwtA = MakeJwt(_deviceId, _deviceKey, sessionA);
        var rejectRespA = await _client.PostAsJsonAsync("/api/auth/reject", new
        {
            session_id = sessionA,
            device_id = _deviceId.ToString(),
            reason = "not_my_pc",
            jwt = rejectJwtA
        });
        Assert.Equal(HttpStatusCode.OK, rejectRespA.StatusCode);

        var outcomeA = await waitA;
        Assert.Equal(PushAuthOutcomeStatus.Rejected, outcomeA.Status);

        // Session B is still pending — confirm it independently with a successful /respond.
        Assert.False(waitB.IsCompleted);
        var responseTsB = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var respondJwtB = MakeJwt(_deviceId, _deviceKey, sessionB);
        var respondRespB = await _client.PostAsJsonAsync("/api/auth/respond", new
        {
            session_id = sessionB,
            device_id = _deviceId.ToString(),
            hmac = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            response_ts = responseTsB,
            jwt = respondJwtB
        });
        Assert.Equal(HttpStatusCode.OK, respondRespB.StatusCode);

        var outcomeB = await waitB;
        Assert.Equal(PushAuthOutcomeStatus.Ok, outcomeB.Status);
        Assert.Equal(responseTsB, outcomeB.ResponseTimestamp);

        // Both sessions are gone from the relay now (each resolves/removes itself) — a third
        // unrelated wait on either id correctly reports "no such session" rather than reusing state.
        Assert.False(_server.TryGetSession(sessionA, out _));
        Assert.False(_server.TryGetSession(sessionB, out _));
    }
}
