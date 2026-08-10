using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WindowsGoodBye.Core;

namespace WindowsGoodBye.Service;

/// <summary>
/// Embedded ASP.NET Minimal API relay for push-auth (Ruta C). Binds to
/// <c>http://localhost:{port}</c> ONLY — never <c>0.0.0.0</c>. Internet reachability is provided
/// entirely by Cloudflare Tunnel (see <see cref="TunnelManager"/>), which forwards to this loopback
/// port; the relay itself never listens on a non-loopback address.
///
/// See docs/plan_push_auth_v2.md:
/// - "🛠️ Relay HTTP Server Embebido — Diseño" (endpoints, PendingSession)
/// - "🛡️ Rate Limiting en el Relay" (exact limits — see <see cref="RelayLimits"/>)
/// - "🛡️ Aislamiento y Resiliencia del Relay" (exception middleware, body-size/timeouts — the
///   critical audit finding: this process also hosts AuthWorker and the CredentialProvider pipe, so
///   an unhandled exception here must never propagate and take the whole Service down with it)
/// - "🛡️ Defensa contra Push Fatigue" (POST /api/auth/reject — explicit rejection, distinct from timeout)
///
/// Nomenclature note (see plan's intro note): AuthWorker (Fase 3) does NOT call this class's HTTP
/// endpoints over the network to register/await its own sessions — it's the same process. Use
/// <see cref="RegisterSessionDirect"/> / <see cref="WaitForResponseDirectAsync"/> /
/// <see cref="RemoveSession"/> instead, which operate on the exact same <see cref="_sessions"/>
/// dictionary that the HTTP handlers use for Android's real (tunnel-borne) requests. The HTTP
/// <c>/api/auth/register</c> and <c>/api/auth/wait/{sid}</c> endpoints still exist (per the plan's
/// literal endpoint table, and so the whole register→wait→respond flow is testable end-to-end over
/// HTTP), but production code should prefer the direct, in-process API to avoid a pointless
/// loopback HTTP round-trip and JWT round-trip for something the Service already trusts itself on.
/// </summary>
public sealed class RelayServer : IAsyncDisposable
{
    private const string ValidatedDeviceIdKey = "wingb.relay.device_id";
    private const string ValidatedSessionIdKey = "wingb.relay.session_id";
    private const string RegisterPolicy = "wingb-relay-register";
    private const string DeviceTokenPolicy = "wingb-relay-device-token";

    private readonly ILogger<RelayServer> _logger;
    private readonly Func<string, byte[]?> _resolveRelayKey;
    private readonly int _port;
    private readonly ConcurrentDictionary<string, SessionEntry> _sessions = new();

    private WebApplication? _app;

    /// <summary>Raised when Android POSTs a rotated FCM token via <c>/api/device/token</c> (Fase 8 hook).</summary>
    public event Action<string, string>? FcmTokenUpdateReceived;

    /// <summary>
    /// The actual TCP port Kestrel bound to after <see cref="StartAsync"/> — useful in tests, where
    /// the server is started with <paramref name="port"/> = 0 (OS-assigned free port) to avoid
    /// collisions with a real, already-running Service instance.
    /// </summary>
    public int? BoundPort { get; private set; }

    public bool IsRunning => _app != null;

    /// <param name="logger">Logger for relay lifecycle/security events.</param>
    /// <param name="resolveRelayKey">
    /// Resolves <c>device_id</c> (string form of <see cref="DeviceInfo.DeviceId"/>) to that device's
    /// <see cref="RelayKeyDerivation.DeriveRelayKey"/> output, or null if the device is unknown/disabled.
    /// Deliberately a delegate rather than a direct <c>AppDatabase</c> dependency so Fase 2 doesn't need
    /// to take on EF Core wiring here, and so tests can supply an in-memory fake.
    /// </param>
    /// <param name="port">
    /// Loopback port to bind. Defaults to <see cref="Protocol.RelayPort"/>. Pass 0 in tests to let the
    /// OS assign a free port (read back via <see cref="BoundPort"/>).
    /// </param>
    public RelayServer(ILogger<RelayServer> logger, Func<string, byte[]?> resolveRelayKey, int port = Protocol.RelayPort)
    {
        _logger = logger;
        _resolveRelayKey = resolveRelayKey;
        _port = port;
    }

    // ============================================================================================
    // Lifecycle
    // ============================================================================================

    public async Task StartAsync(CancellationToken ct = default)
    {
        if (_app != null) return;

        var builder = WebApplication.CreateSlimBuilder();

        // Slim builder still wires the default console logging provider, which is undesirable inside
        // a Windows Service (no console). Route everything through the ILogger we were given instead.
        builder.Logging.ClearProviders();

        builder.WebHost.ConfigureKestrel(o =>
        {
            // "🛡️ Aislamiento y Resiliencia del Relay": body-size cap + explicit timeouts so a
            // slow/malicious connection or an oversized payload can't exhaust the shared process.
            o.Limits.MaxRequestBodySize = RelayLimits.MaxRequestBodyBytes;
            o.Limits.MinRequestBodyDataRate = new MinDataRate(bytesPerSecond: 100, gracePeriod: TimeSpan.FromSeconds(5));
            o.Limits.MinResponseDataRate = new MinDataRate(bytesPerSecond: 100, gracePeriod: TimeSpan.FromSeconds(5));
            o.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
            o.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(30);
            o.Limits.MaxConcurrentConnections = 100;
        });

        // Loopback-only. Never UseUrls("http://0.0.0.0:...") or "http://*:...". Internet reachability
        // comes exclusively from Cloudflare Tunnel forwarding into this address — see TunnelManager.
        // Uses the literal 127.0.0.1 address rather than the "localhost" host name: Kestrel's
        // "localhost" binding is a special dual-stack alias that explicitly rejects dynamic port 0
        // ("Dynamic port binding is not supported when binding to localhost"), which tests rely on
        // (port: 0 → OS-assigned free port, see BoundPort). 127.0.0.1 is exactly as loopback-only as
        // "localhost" — this is not a security-relevant change, just an addressing one.
        builder.WebHost.UseUrls($"http://127.0.0.1:{_port}");

        ConfigureRateLimiting(builder.Services);

        _app = builder.Build();

        // 1) Global exception-handling middleware — FIRST in the pipeline, wraps every request
        //    (including /health). This is the critical audit mitigation: RelayServer shares a process
        //    with AuthWorker/the CredentialProvider pipe, so an unhandled exception here must turn into
        //    a logged 500, never an unhandled exception that crashes the whole Service.
        _app.Use(ExceptionHandlingMiddlewareAsync);

        // 2) Rate limiting — global (100/min/IP) + named per-endpoint policies.
        _app.UseRateLimiter();

        // 3) JWT validation for every endpoint except /api/health.
        _app.Use(JwtValidationMiddlewareAsync);

        _app.MapGet("/api/health", () => Results.Ok(new { status = "ok" }));

        _app.MapPost("/api/auth/register", RegisterSessionEndpoint).RequireRateLimiting(RegisterPolicy);
        _app.MapGet("/api/auth/wait/{sessionId}", WaitForResponseEndpoint);
        _app.MapPost("/api/auth/respond", SubmitResponseEndpoint);
        _app.MapPost("/api/auth/reject", SubmitRejectEndpoint);
        _app.MapPost("/api/device/token", UpdateFcmTokenEndpoint).RequireRateLimiting(DeviceTokenPolicy);

        await _app.StartAsync(ct);

        var addressesFeature = _app.Services.GetService<IServer>()?.Features.Get<IServerAddressesFeature>();
        var boundAddress = addressesFeature?.Addresses.FirstOrDefault();
        BoundPort = boundAddress != null ? new Uri(boundAddress).Port : _port;

        _logger.LogInformation("Relay server listening on http://localhost:{Port} (loopback-only)", BoundPort);
    }

    public async Task StopAsync(CancellationToken ct = default)
    {
        if (_app == null) return;
        await _app.StopAsync(ct);
        await _app.DisposeAsync();
        _app = null;
        BoundPort = null;
    }

    public async ValueTask DisposeAsync()
    {
        if (_app != null) await StopAsync();
    }

    // ============================================================================================
    // In-process API for AuthWorker (Fase 3) — bypasses HTTP/JWT entirely, same trust boundary as
    // the rest of the Service process. Shares the exact same _sessions dictionary the HTTP handlers
    // use, so a response Android POSTs over the tunnel resolves whatever AuthWorker registered here.
    // ============================================================================================

    /// <summary>
    /// Register a pending push-auth session. <paramref name="nonce"/>/<paramref name="displayCode"/>
    /// are stored only because the caller (AuthWorker) may find it convenient to fetch them back via
    /// <see cref="TryGetSession"/> from this shared instance; the relay itself never reads or needs
    /// them for its own logic.
    /// </summary>
    public PushAuthSession RegisterSessionDirect(
        string sessionId, Guid deviceId, byte[] nonce, string displayCode, int attemptNumber, TimeSpan? ttl = null)
    {
        var session = BuildSession(sessionId, deviceId, nonce, displayCode, attemptNumber, ttl);
        _sessions[sessionId] = new SessionEntry { Session = session };
        return session;
    }

    /// <summary>
    /// Await Android's response/rejection for a session registered via <see cref="RegisterSessionDirect"/>,
    /// honoring the session's own TTL and <paramref name="ct"/> (e.g. the CP-side global timeout or a
    /// cross-route cancellation when another race leg — Ruta A/B — wins first).
    /// </summary>
    public async Task<PushAuthOutcome> WaitForResponseDirectAsync(string sessionId, CancellationToken ct)
    {
        if (!_sessions.TryGetValue(sessionId, out var entry))
            return new PushAuthOutcome(PushAuthOutcomeStatus.Expired);

        return await AwaitEntryAsync(entry, ct);
    }

    /// <summary>Inspect a still-pending session (e.g. to read back its DisplayCode/Nonce). Does not remove it.</summary>
    public bool TryGetSession(string sessionId, out PushAuthSession? session)
    {
        if (_sessions.TryGetValue(sessionId, out var entry))
        {
            session = entry.Session;
            return true;
        }
        session = null;
        return false;
    }

    /// <summary>
    /// Remove a session without waiting for its natural resolution — used when a different race leg
    /// (Ruta A/B) wins first and Ruta C's relay session should stop accepting a late Android response.
    /// </summary>
    public bool RemoveSession(string sessionId) => _sessions.TryRemove(sessionId, out _);

    // ============================================================================================
    // Pipeline middleware
    // ============================================================================================

    private async Task ExceptionHandlingMiddlewareAsync(HttpContext ctx, Func<Task> next)
    {
        try
        {
            await next();
        }
        catch (Microsoft.AspNetCore.Http.BadHttpRequestException badRequest)
        {
            // Typically thrown when a request exceeds Kestrel.Limits.MaxRequestBodySize, or is
            // otherwise malformed at the transport level. Preserve its status code (usually 400/413)
            // instead of collapsing it into a generic 500.
            _logger.LogWarning(badRequest, "Relay: bad request {Method} {Path}", ctx.Request.Method, ctx.Request.Path);
            if (!ctx.Response.HasStarted)
            {
                ctx.Response.Clear();
                ctx.Response.StatusCode = badRequest.StatusCode is >= 400 and < 500
                    ? badRequest.StatusCode
                    : StatusCodes.Status400BadRequest;
                await WriteJsonAsync(ctx, ctx.Response.StatusCode, new { error = "bad_request" });
            }
        }
        catch (Exception ex)
        {
            // Critical mitigation (see "🛡️ Aislamiento y Resiliencia del Relay"): never let an
            // unhandled exception escape this middleware — this process also hosts AuthWorker and the
            // CredentialProvider pipe (Ruta A), so a crash here would take real Windows logins down too.
            _logger.LogError(ex, "Relay: unhandled exception in {Method} {Path} — returning 500, Service stays up",
                ctx.Request.Method, ctx.Request.Path);
            if (!ctx.Response.HasStarted)
            {
                ctx.Response.Clear();
                ctx.Response.StatusCode = StatusCodes.Status500InternalServerError;
                await WriteJsonAsync(ctx, 500, new { error = "internal_error" });
            }
        }
    }

    private async Task JwtValidationMiddlewareAsync(HttpContext ctx, Func<Task> next)
    {
        if (ctx.Request.Path.StartsWithSegments("/api/health"))
        {
            await next();
            return;
        }

        var (deviceId, jwt) = await ExtractCredentialsAsync(ctx);
        if (string.IsNullOrEmpty(jwt) || string.IsNullOrEmpty(deviceId))
        {
            await WriteJsonAsync(ctx, StatusCodes.Status401Unauthorized, new { error = "missing_credentials" });
            return;
        }

        var relayKey = _resolveRelayKey(deviceId);
        if (relayKey == null)
        {
            _logger.LogWarning("Relay: unknown device_id {DeviceId} from {IP}", deviceId, ctx.Connection.RemoteIpAddress);
            await WriteJsonAsync(ctx, StatusCodes.Status401Unauthorized, new { error = "unknown_device" });
            return;
        }

        if (!JwtHelper.TryValidateToken(jwt, relayKey, out var payload, out var error) || payload!.Sub != deviceId)
        {
            _logger.LogWarning("Relay: JWT validation failed for {DeviceId}: {Error}", deviceId, error);
            await WriteJsonAsync(ctx, StatusCodes.Status401Unauthorized, new { error = "invalid_token" });
            return;
        }

        ctx.Items[ValidatedDeviceIdKey] = deviceId;
        ctx.Items[ValidatedSessionIdKey] = payload.Sid;
        await next();
    }

    /// <summary>
    /// Pulls (device_id, jwt) out of the request without letting either endpoint's own model binding
    /// consume the body stream first. POST bodies are read once here (buffered so downstream Minimal
    /// API binding can still read them), the GET /wait endpoint takes its JWT from the
    /// <c>Authorization: Bearer</c> header or a <c>?jwt=</c> query fallback (a deliberate deviation
    /// from the plan's illustrative "GET with a JSON body" snippet — GET requests conventionally carry
    /// no body, and Minimal API route binding for <c>/wait/{sessionId}</c> doesn't need one).
    /// </summary>
    private static async Task<(string? deviceId, string? jwt)> ExtractCredentialsAsync(HttpContext ctx)
    {
        if (HttpMethods.IsGet(ctx.Request.Method))
        {
            var header = ctx.Request.Headers.Authorization.ToString();
            var jwt = header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                ? header["Bearer ".Length..]
                : ctx.Request.Query["jwt"].ToString();

            if (string.IsNullOrEmpty(jwt) || jwt.Length > RelayLimits.MaxJwtLength) return (null, null);
            return (JwtHelper.PeekSubjectUnsafe(jwt), jwt);
        }

        ctx.Request.EnableBuffering();
        string bodyText;
        using (var reader = new StreamReader(ctx.Request.Body, Encoding.UTF8, detectEncodingFromByteOrderMarks: false,
                   bufferSize: 4096, leaveOpen: true))
        {
            bodyText = await reader.ReadToEndAsync();
        }
        ctx.Request.Body.Position = 0;

        try
        {
            using var doc = JsonDocument.Parse(bodyText);
            var root = doc.RootElement;
            var jwt = root.TryGetProperty("jwt", out var jwtEl) ? jwtEl.GetString() : null;
            var deviceId = root.TryGetProperty("device_id", out var devEl) ? devEl.GetString()
                : root.TryGetProperty("expected_device_id", out var expEl) ? expEl.GetString() : null;

            if (string.IsNullOrEmpty(jwt) || jwt.Length > RelayLimits.MaxJwtLength) return (null, null);
            if (string.IsNullOrEmpty(deviceId) || deviceId.Length > RelayLimits.MaxDeviceIdLength) return (null, null);
            return (deviceId, jwt);
        }
        catch (JsonException)
        {
            return (null, null);
        }
    }

    private static async Task WriteJsonAsync(HttpContext ctx, int statusCode, object body)
    {
        ctx.Response.StatusCode = statusCode;
        ctx.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(ctx.Response.Body, body);
    }

    // ============================================================================================
    // Rate limiting — see "🛡️ Rate Limiting en el Relay" for the exact values (centralized in
    // RelayLimits). /api/auth/respond (5 attempts/session → 403 + invalidate) and
    // /api/auth/wait/{sid} (1 concurrent/session → 409) are NOT expressed here: their remediation is
    // bespoke business logic (kill the session / reject the duplicate poll), not a generic 429, so
    // they're implemented directly in their handlers below instead of as RateLimiting policies.
    // ============================================================================================

    private static void ConfigureRateLimiting(IServiceCollection services)
    {
        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            // Global: 100 req/min per IP, applies to every endpoint (including ones with their own
            // named policy below — RateLimiting evaluates the global limiter AND any named policy).
            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
            {
                var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                return RateLimitPartition.GetFixedWindowLimiter(ip, _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = RelayLimits.GlobalPerMinutePerIp,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0
                });
            });

            // POST /api/auth/register: 10 req/min per IP.
            options.AddPolicy(RegisterPolicy, ctx =>
            {
                var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                return RateLimitPartition.GetFixedWindowLimiter(ip, _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = RelayLimits.RegisterPerMinutePerIp,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0
                });
            });

            // POST /api/device/token: 5 req/min per device_id. Partitioned by the device_id the JWT
            // middleware already validated (that middleware runs BEFORE UseRateLimiter in the
            // pipeline, so ctx.Items is populated by the time this partition function runs).
            options.AddPolicy(DeviceTokenPolicy, ctx =>
            {
                var deviceId = ctx.Items.TryGetValue(ValidatedDeviceIdKey, out var v) ? v as string : null;
                return RateLimitPartition.GetFixedWindowLimiter(deviceId ?? "unknown", _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = RelayLimits.DeviceTokenPerMinutePerDeviceId,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0
                });
            });
        });
    }

    // ============================================================================================
    // Endpoint handlers
    // ============================================================================================

    private IResult RegisterSessionEndpoint(HttpContext ctx, RegisterRequest req)
    {
        if (!req.TryValidate(out var validationError))
            return Results.BadRequest(new { error = validationError });

        if (!MatchesValidatedSession(ctx, req.SessionId))
            return Results.Json(new { error = "session_mismatch" }, statusCode: StatusCodes.Status403Forbidden);

        if (!Guid.TryParse(req.ExpectedDeviceId, out var deviceIdGuid))
            return Results.BadRequest(new { error = "invalid expected_device_id" });

        if (_sessions.ContainsKey(req.SessionId))
            return Results.Json(new { error = "session_already_exists" }, statusCode: StatusCodes.Status409Conflict);

        // HTTP-registered sessions carry no nonce/display_code — those only matter to whichever side
        // already has them locally. See the RegisterRequest XML doc for why.
        RegisterSessionDirect(req.SessionId, deviceIdGuid, nonce: Array.Empty<byte>(), displayCode: "", attemptNumber: 1);
        return Results.Ok(new { status = "registered", session_id = req.SessionId });
    }

    private async Task<IResult> WaitForResponseEndpoint(HttpContext ctx, string sessionId, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(sessionId) || sessionId.Length > RelayLimits.MaxSessionIdLength)
            return Results.BadRequest(new { error = "invalid session_id" });

        if (!MatchesValidatedSession(ctx, sessionId))
            return Results.Json(new { error = "session_mismatch" }, statusCode: StatusCodes.Status403Forbidden);

        if (!_sessions.TryGetValue(sessionId, out var entry))
            return Results.Json(new { status = "expired" }, statusCode: StatusCodes.Status408RequestTimeout);

        // "GET /api/auth/wait/{sid} | 1 conexión concurrente | por session_id | 409 Conflict"
        if (Interlocked.CompareExchange(ref entry.WaitInProgress, 1, 0) != 0)
            return Results.Json(new { error = "wait_in_progress" }, statusCode: StatusCodes.Status409Conflict);

        try
        {
            var outcome = await AwaitEntryAsync(entry, ct);
            return ToResult(outcome);
        }
        finally
        {
            Interlocked.Exchange(ref entry.WaitInProgress, 0);
        }
    }

    private IResult SubmitResponseEndpoint(HttpContext ctx, RespondRequest req)
    {
        if (!req.TryValidate(out var validationError))
            return Results.BadRequest(new { error = validationError });

        if (!MatchesValidatedSession(ctx, req.SessionId))
            return Results.Json(new { error = "session_mismatch" }, statusCode: StatusCodes.Status403Forbidden);

        if (!_sessions.TryGetValue(req.SessionId, out var entry))
            return Results.NotFound(new { error = "session_not_found" });

        // "POST /api/auth/respond | 5 intentos | por session_id | 403 Forbidden + invalida la sesión"
        var attempts = Interlocked.Increment(ref entry.RespondAttempts);
        if (attempts > RelayLimits.MaxRespondAttemptsPerSession)
        {
            _sessions.TryRemove(req.SessionId, out _);
            _logger.LogWarning("Relay: session {SessionId} exceeded {Max} /respond attempts — session invalidated",
                req.SessionId, RelayLimits.MaxRespondAttemptsPerSession);
            return Results.Json(new { error = "too_many_attempts" }, statusCode: StatusCodes.Status403Forbidden);
        }

        if (entry.Session.ExpiresAt < DateTimeOffset.UtcNow)
        {
            _sessions.TryRemove(req.SessionId, out _);
            return Results.Json(new { status = "expired" }, statusCode: StatusCodes.Status408RequestTimeout);
        }

        // Session-device binding — see "Binding de Session-Device en el Relay" (Fisura #7).
        if (!Guid.TryParse(req.DeviceId, out var deviceIdGuid) || deviceIdGuid != entry.Session.DeviceId)
        {
            _logger.LogWarning("Relay: /respond device_id mismatch for session {SessionId}", req.SessionId);
            return Results.Json(new { error = "device_id_mismatch" }, statusCode: StatusCodes.Status403Forbidden);
        }

        var outcome = new PushAuthOutcome(PushAuthOutcomeStatus.Ok, req.DeviceId, req.Hmac, req.ResponseTimestamp);
        if (!entry.Tcs.TrySetResult(outcome))
            return Results.Conflict(new { error = "already_responded" });

        return Results.Ok(new { status = "ok" });
    }

    private IResult SubmitRejectEndpoint(HttpContext ctx, RejectRequest req)
    {
        if (!req.TryValidate(out var validationError))
            return Results.BadRequest(new { error = validationError });

        if (!MatchesValidatedSession(ctx, req.SessionId))
            return Results.Json(new { error = "session_mismatch" }, statusCode: StatusCodes.Status403Forbidden);

        if (!_sessions.TryGetValue(req.SessionId, out var entry))
            return Results.NotFound(new { error = "session_not_found" });

        if (!Guid.TryParse(req.DeviceId, out var deviceIdGuid) || deviceIdGuid != entry.Session.DeviceId)
            return Results.Json(new { error = "device_id_mismatch" }, statusCode: StatusCodes.Status403Forbidden);

        var outcome = new PushAuthOutcome(PushAuthOutcomeStatus.Rejected, req.DeviceId, RejectReason: req.Reason);
        _sessions.TryRemove(req.SessionId, out _);
        entry.Tcs.TrySetResult(outcome);

        _logger.LogInformation("Relay: session {SessionId} explicitly rejected by device {DeviceId}{Reason}",
            req.SessionId, req.DeviceId, req.Reason != null ? $" ({req.Reason})" : "");
        return Results.Ok(new { status = "rejected" });
    }

    private IResult UpdateFcmTokenEndpoint(HttpContext ctx, TokenUpdateRequest req)
    {
        if (!req.TryValidate(out var validationError))
            return Results.BadRequest(new { error = validationError });

        // The JWT middleware already confirmed the caller's validated device_id matches this body's
        // device_id (both are extracted from the same "device_id" field — see ExtractCredentialsAsync).
        FcmTokenUpdateReceived?.Invoke(req.DeviceId, req.Token);
        _logger.LogInformation("Relay: FCM token update received for device {DeviceId}", req.DeviceId);
        return Results.Ok(new { status = "ok" });
    }

    // ============================================================================================
    // Shared helpers
    // ============================================================================================

    private static bool MatchesValidatedSession(HttpContext ctx, string sessionId) =>
        !ctx.Items.TryGetValue(ValidatedSessionIdKey, out var sidObj) || sidObj as string == sessionId;

    private static PushAuthSession BuildSession(
        string sessionId, Guid deviceId, byte[] nonce, string displayCode, int attemptNumber, TimeSpan? ttl)
    {
        var now = DateTimeOffset.UtcNow;
        return new PushAuthSession
        {
            SessionId = sessionId,
            DeviceId = deviceId,
            Nonce = nonce,
            ChallengeTimestamp = now,
            ExpiresAt = now.Add(ttl ?? TimeSpan.FromSeconds(60)),
            DisplayCode = displayCode,
            AttemptNumber = attemptNumber
        };
    }

    private async Task<PushAuthOutcome> AwaitEntryAsync(SessionEntry entry, CancellationToken ct)
    {
        var remaining = entry.Session.ExpiresAt - DateTimeOffset.UtcNow;
        if (remaining <= TimeSpan.Zero)
        {
            _sessions.TryRemove(entry.Session.SessionId, out _);
            return new PushAuthOutcome(PushAuthOutcomeStatus.Expired);
        }

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(remaining);

        try
        {
            var outcome = await entry.Tcs.Task.WaitAsync(timeoutCts.Token);
            _sessions.TryRemove(entry.Session.SessionId, out _);
            return outcome;
        }
        catch (OperationCanceledException)
        {
            _sessions.TryRemove(entry.Session.SessionId, out _);
            return new PushAuthOutcome(PushAuthOutcomeStatus.Timeout);
        }
    }

    private static IResult ToResult(PushAuthOutcome outcome) => outcome.Status switch
    {
        PushAuthOutcomeStatus.Ok => Results.Ok(new
        {
            status = "ok",
            device_id = outcome.DeviceId,
            hmac = outcome.Hmac,
            response_ts = outcome.ResponseTimestamp
        }),
        PushAuthOutcomeStatus.Rejected => Results.Ok(new { status = "rejected", reason = outcome.RejectReason }),
        PushAuthOutcomeStatus.Expired => Results.Json(new { status = "expired" }, statusCode: StatusCodes.Status408RequestTimeout),
        PushAuthOutcomeStatus.Timeout => Results.Json(new { status = "timeout" }, statusCode: StatusCodes.Status408RequestTimeout),
        _ => Results.Problem()
    };

    /// <summary>Per-session mutable state layered on top of the immutable <see cref="PushAuthSession"/> data.</summary>
    private sealed class SessionEntry
    {
        public required PushAuthSession Session { get; init; }
        public readonly TaskCompletionSource<PushAuthOutcome> Tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int RespondAttempts;
        public int WaitInProgress;
    }
}
