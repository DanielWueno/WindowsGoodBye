using System.Net.Http.Json;
using System.Reflection;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using WindowsGoodBye.Core;
using WindowsGoodBye.Service;
using Xunit;

namespace WindowsGoodBye.Service.Tests;

/// <summary>
/// Fase 13 (Testing &amp; Polish) — real-<see cref="AuthWorker"/>-level coverage of
/// docs/plan_push_auth_v2.md's "🔄 Algoritmo de Decisión del Modo Hybrid" (Fase 13 test table:
/// "AuthWorker.RunAuthRaceAsync() con Ruta A ganando, Ruta C ganando, timeout global sin ninguna ruta,
/// cancelación cruzada de rutas perdedoras"). Everything through Fase 3 tested the individual pieces in
/// isolation (<see cref="AuthRaceCombinatorTests"/>: the combinator alone; <see cref="AuthWorkerHmacVerificationTests"/>:
/// HMAC/timestamp verification alone; <see cref="RelayServerTests"/>: the relay's HTTP surface alone) —
/// see docs/implementation_progress_push_auth_v2.md, Fase 3 notes ("no fue posible testear
/// RunAuthRaceAsync/TryPushAuthAsync de punta a punta ... refactor grande no barato"). This file closes
/// as much of that gap as is safely possible WITHOUT the refactor those notes ruled out:
/// <list type="bullet">
/// <item><description>Constructs a REAL <see cref="AuthWorker"/> via its existing public constructor
/// (<c>RelayServer</c>/<c>ITunnelStatusProvider</c> are already optional DI seams from Fase 3/4) instead
/// of the full DI host.</description></item>
/// <item><description>Uses reflection ONLY to set the two private fields (<c>_db</c>, <c>_fcm</c>) that
/// Fase 3 never exposed a constructor seam for, because <c>ExecuteAsync</c> (which normally sets them)
/// also starts real Bluetooth/TCP/UDP listeners this test process must never start.</description></item>
/// <item><description>A minimal, additive change to <see cref="FcmPushSender"/> (two <c>virtual</c>
/// keywords, zero behavior change — see that file's remarks) so a fake subclass can stand in for real
/// FCM/OAuth2 network calls without ever touching the network.</description></item>
/// </list>
///
/// <b>Deliberately NOT covered here (and why)</b>: a literal "Ruta A/C gana" SUCCESS outcome.
/// <see cref="AuthWorker"/>'s single completion path (<c>CompleteAuthentication</c>) unconditionally
/// opens <c>new AppDatabase()</c> — the PARAMETERLESS constructor, hardcoded to the real
/// <c>%ProgramData%\WindowsGoodBye\devices.db</c> — to read stored credentials. Driving a real success
/// through it in an automated test would touch that real, per-machine path, which this whole batch's
/// rules explicitly forbid ("no tocar ... sistema real"). This is a structural property of the existing
/// production code, not a shortcut taken here, and fixing it would mean changing Fase 3's completion
/// logic — out of scope for a Fase 13 (testing/polish) pass. The SUCCESS-path semantics that matter most
/// (HMAC/timestamp correctness, "first success wins" combinator logic, relay session-device binding) are
/// already fully covered by <see cref="AuthWorkerHmacVerificationTests"/>/<see cref="AuthRaceCombinatorTests"/>/
/// <see cref="RelayServerTests"/>; what remains untested end-to-end is narrowly "does TryPushAuthAsync
/// call CompleteAuthentication given a genuinely-Ok outcome", verified only by code inspection — see
/// docs/implementation_progress_push_auth_v2.md, Fase 13 notes.
///
/// Also documents an honest finding (not fixed here, see the same notes): <c>RunAuthRaceAsync</c> does
/// NOT actively cancel other legs the instant one leg succeeds — it relies on the 60s global timeout
/// (<c>raceCts.CancelAfter</c>) to eventually unblock abandoned legs, plus each leg's own cleanup
/// (<c>TryPushAuthAsync</c>'s <c>finally</c> removing its relay session). This is a real, if minor,
/// deviation from the plan's literal "el CancellationToken cancela las demás rutas" wording — losing
/// legs are cleaned up cooperatively/eventually, not instantly. The tests below characterize the
/// eventual-cleanup behavior that DOES exist.
/// </summary>
public sealed class AuthWorkerRaceIntegrationTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"wingb-race-test-{Guid.NewGuid():n}.db");
    private readonly List<RelayServer> _relaysToDispose = new();

    public void Dispose()
    {
        foreach (var relay in _relaysToDispose)
        {
            try { relay.DisposeAsync().AsTask().GetAwaiter().GetResult(); } catch { /* best effort */ }
        }
        try { File.Delete(_dbPath); } catch { /* best effort */ }
    }

    // ---- test scaffolding -----------------------------------------------------------------------

    private static readonly IConfiguration EmptyConfig = new ConfigurationBuilder().Build();

    private sealed class FakeTunnelStatusProvider : ITunnelStatusProvider
    {
        public bool IsConnected { get; set; }
        public string? PublicUrl => IsConnected ? "https://fake.trycloudflare.com" : null;
    }

    /// <summary>
    /// Stands in for real FCM: never touches the network (OAuth2/fcm.googleapis.com). The optional
    /// <paramref name="onChallengeSent"/> callback lets a test synchronously simulate "Android received
    /// the push and replied" (e.g. POST /api/auth/reject to the SAME in-test <see cref="RelayServer"/>)
    /// before this returns — deterministic, no timing races/sleeps needed.
    /// </summary>
    private sealed class FakeFcmPushSender : FcmPushSender
    {
        private readonly Func<IDictionary<string, string>, Task>? _onChallengeSent;
        public List<IDictionary<string, string>> SentMessages { get; } = new();
        public override bool IsAvailable => true;

        public FakeFcmPushSender(Func<IDictionary<string, string>, Task>? onChallengeSent = null)
            : base(NullLogger<FcmPushSender>.Instance, EmptyConfig)
        {
            _onChallengeSent = onChallengeSent;
        }

        public override async Task<FcmSendResult> SendDataMessageAsync(string fcmToken, IDictionary<string, string> data)
        {
            SentMessages.Add(data);

            // Ruta B (legacy "auth_wake") fires for ANY FCM-valid device whenever there's no active
            // direct transport — regardless of PushAuthEnabled — so it shows up here too whenever a
            // test's device has FcmTokenValid+FcmToken set. Only full push-auth challenges
            // (action == Protocol.PushAuthChallenge) carry a session_id/device_id worth reacting to.
            if (_onChallengeSent != null && data.TryGetValue("action", out var action) && action == Protocol.PushAuthChallenge)
                await _onChallengeSent(data);

            return FcmSendResult.Success;
        }

        /// <summary>Only the full push-auth challenges (Ruta C) — excludes Ruta B's legacy "auth_wake" nudges.</summary>
        public IReadOnlyList<IDictionary<string, string>> Challenges =>
            SentMessages.Where(m => m.TryGetValue("action", out var a) && a == Protocol.PushAuthChallenge).ToList();
    }

    private AppDatabase NewDb()
    {
        var db = new AppDatabase(_dbPath);
        db.Initialize();
        return db;
    }

    private static void SetPrivateField(AuthWorker worker, string fieldName, object? value)
    {
        var field = typeof(AuthWorker).GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new InvalidOperationException($"AuthWorker.{fieldName} not found — did the field get renamed?");
        field.SetValue(worker, value);
    }

    /// <summary>
    /// Builds a real, started <see cref="RelayServer"/> (loopback, OS-assigned port) plus a real
    /// <see cref="AuthWorker"/> wired directly to it and to a throwaway SQLite file — bypassing the full
    /// DI host (<c>Program.cs</c>) and <c>ExecuteAsync</c> (which would start real Bluetooth/TCP/UDP
    /// listeners and touch the real, per-machine <c>AppDatabase()</c> default path).
    /// </summary>
    private async Task<(AuthWorker Worker, RelayServer Relay, FakeFcmPushSender Fcm, AppDatabase Db)> BuildWorkerAsync(
        FakeTunnelStatusProvider tunnel, int globalTimeoutSeconds, FakeFcmPushSender? fcm = null)
    {
        var db = NewDb();
        var dbPath = _dbPath;

        byte[]? ResolveRelayKey(string deviceIdStr)
        {
            if (!Guid.TryParse(deviceIdStr, out var id)) return null;
            using var lookupDb = new AppDatabase(dbPath);
            var device = lookupDb.Devices.Find(id);
            return device is { Enabled: true } ? RelayKeyDerivation.DeriveRelayKey(device.DeviceKey) : null;
        }

        var relay = new RelayServer(NullLogger<RelayServer>.Instance, ResolveRelayKey, port: 0);
        await relay.StartAsync();
        _relaysToDispose.Add(relay);

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PushAuth:GlobalTimeoutSeconds"] = globalTimeoutSeconds.ToString()
            })
            .Build();

        var worker = new AuthWorker(NullLogger<AuthWorker>.Instance, NullLoggerFactory.Instance, config, relay, tunnel);
        var effectiveFcm = fcm ?? new FakeFcmPushSender();
        SetPrivateField(worker, "_db", db);
        SetPrivateField(worker, "_fcm", effectiveFcm);

        return (worker, relay, effectiveFcm, db);
    }

    private static DeviceInfo NewDevice(bool pushAuthEnabled = false, bool fcmTokenValid = false, string? fcmToken = null) => new()
    {
        DeviceId = Guid.NewGuid(),
        DeviceKey = RandomNumberGenerator.GetBytes(32),
        AuthKey = RandomNumberGenerator.GetBytes(32),
        Enabled = true,
        PushAuthEnabled = pushAuthEnabled,
        FcmTokenValid = fcmTokenValid,
        FcmToken = fcmToken
    };

    // ---- tests ----------------------------------------------------------------------------------

    /// <summary>
    /// "Push fatigue ... debe aplicar incluso si Ruta A/B ... es la que dispara los intentos" — verified
    /// here at the REAL <c>RunAuthRaceAsync</c> entry point (not just the isolated
    /// <see cref="PushFatigueGuard"/> unit tests). Also doubles as the "timeout global sin ninguna ruta
    /// responde" case for its first call: with the tunnel disconnected, only the legacy Ruta A/B leg
    /// exists, nobody ever signals <c>AuthWorker.AuthEvent</c>, so it resolves via the configured global
    /// timeout (kept short here so the test stays fast) without ever reaching CompleteAuthentication.
    /// </summary>
    [Fact]
    public async Task PushFatigueGuard_GatesRealEntryPoint_AndFirstCallTimesOutWithNoRouteResponding()
    {
        var tunnel = new FakeTunnelStatusProvider { IsConnected = false };
        var (worker, _, _, db) = await BuildWorkerAsync(tunnel, globalTimeoutSeconds: 1);
        db.Devices.Add(NewDevice());
        db.SaveChanges();

        var firstStatuses = new List<string>();
        var firstOutcome = await worker.RunAuthRaceAsync(s => { firstStatuses.Add(s); return Task.CompletedTask; }, CancellationToken.None);

        Assert.False(firstOutcome.Success);
        Assert.Contains("searching", firstStatuses);
        Assert.Contains("timeout", firstStatuses);

        // Second call happens well within the 8s minimum interval — the real entry point must block it
        // before ever reaching "searching"/launching any route, per the plan's push-fatigue rules.
        var secondStatuses = new List<string>();
        var secondOutcome = await worker.RunAuthRaceAsync(s => { secondStatuses.Add(s); return Task.CompletedTask; }, CancellationToken.None);

        Assert.False(secondOutcome.Success);
        Assert.Contains(secondStatuses, s => s.StartsWith("blocked:", StringComparison.Ordinal));
        Assert.DoesNotContain("searching", secondStatuses);
    }

    /// <summary>"SI tunnel.IsConnected Y NO hay transporte directo activo: también lanza Ruta B" / Ruta C
    /// gating — with the tunnel disconnected, Ruta C (and the legacy Ruta B wake) must never fire
    /// regardless of how push-auth-eligible a device is.</summary>
    [Fact]
    public async Task RutaC_NeverLaunches_WhenTunnelDisconnected()
    {
        var tunnel = new FakeTunnelStatusProvider { IsConnected = false };
        var fcm = new FakeFcmPushSender();
        var (worker, _, _, db) = await BuildWorkerAsync(tunnel, globalTimeoutSeconds: 1, fcm: fcm);
        db.Devices.Add(NewDevice(pushAuthEnabled: true, fcmTokenValid: true, fcmToken: "tok"));
        db.SaveChanges();

        var outcome = await worker.RunAuthRaceAsync(_ => Task.CompletedTask, CancellationToken.None);

        Assert.False(outcome.Success);
        Assert.Empty(fcm.SentMessages);
    }

    /// <summary>
    /// Fase 12's per-device toggle (<c>DeviceInfo.PushAuthEnabled</c>) must gate Ruta C independently per
    /// device, even when the tunnel is connected and every OTHER precondition (FcmTokenValid/FcmToken)
    /// is satisfied for both devices.
    /// </summary>
    [Fact]
    public async Task RutaC_RespectsPushAuthEnabledPerDevice()
    {
        var tunnel = new FakeTunnelStatusProvider { IsConnected = true };
        var fcm = new FakeFcmPushSender(); // no auto-responder — both/either challenge just times out
        var (worker, _, _, db) = await BuildWorkerAsync(tunnel, globalTimeoutSeconds: 1, fcm: fcm);

        var disabled = NewDevice(pushAuthEnabled: false, fcmTokenValid: true, fcmToken: "tok-disabled");
        var enabled = NewDevice(pushAuthEnabled: true, fcmTokenValid: true, fcmToken: "tok-enabled");
        db.Devices.Add(disabled);
        db.Devices.Add(enabled);
        db.SaveChanges();

        var outcome = await worker.RunAuthRaceAsync(_ => Task.CompletedTask, CancellationToken.None);

        Assert.False(outcome.Success); // nobody ever answers -> global timeout
        Assert.Single(fcm.Challenges); // exactly one Ruta C challenge, for the enabled device only
        Assert.Equal(enabled.DeviceId.ToString(), fcm.Challenges[0]["device_id"]);
    }

    /// <summary>
    /// End-to-end Ruta C wiring (AuthWorker -&gt; fake FCM -&gt; real embedded RelayServer, real JWT) for a
    /// LOSING outcome: Android explicitly rejects ("No es mi PC"). Confirms the challenge round-trips
    /// correctly and that the losing leg's relay session is cleaned up — the "cancelación cruzada de
    /// rutas perdedoras" case, characterized via the cleanup that actually exists (see class remarks:
    /// not an instant cancel-on-win, but each leg cleans itself up once it resolves) rather than a
    /// fictitious instant-cancellation guarantee the code doesn't actually implement.
    /// </summary>
    [Fact]
    public async Task RutaC_ExplicitRejection_LosesLeg_SessionCleanedUp_OverallTimeout()
    {
        var tunnel = new FakeTunnelStatusProvider { IsConnected = true };
        var device = NewDevice(pushAuthEnabled: true, fcmTokenValid: true, fcmToken: "tok");
        RelayServer? relayRef = null;

        async Task OnChallengeSent(IDictionary<string, string> data)
        {
            var sessionId = data["session_id"];
            var relayKey = RelayKeyDerivation.DeriveRelayKey(device.DeviceKey);
            var jwt = JwtHelper.CreateToken(device.DeviceId.ToString(), sessionId, relayKey);
            using var http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{relayRef!.BoundPort}") };
            var resp = await http.PostAsJsonAsync("/api/auth/reject", new
            {
                session_id = sessionId,
                device_id = device.DeviceId.ToString(),
                reason = "not_my_pc",
                jwt
            });
            resp.EnsureSuccessStatusCode();
        }

        var fcm = new FakeFcmPushSender(OnChallengeSent);
        var (worker, relay, _, db) = await BuildWorkerAsync(tunnel, globalTimeoutSeconds: 2, fcm: fcm);
        relayRef = relay;

        db.Devices.Add(device);
        db.SaveChanges();

        var outcome = await worker.RunAuthRaceAsync(_ => Task.CompletedTask, CancellationToken.None);

        Assert.False(outcome.Success); // rejected leg lost; nothing else ever succeeds -> overall timeout
        Assert.Single(fcm.Challenges);
        var sessionId = fcm.Challenges[0]["session_id"];
        Assert.False(relay.TryGetSession(sessionId, out _)); // cleaned up, not left dangling
    }

    /// <summary>
    /// Multi-device Ruta C (Fase 8 "Múltiples PCs Emparejadas" reasoning, but for multiple PHONES
    /// eligible for the SAME PC's cycle): two independent sessions run concurrently, both lose (one
    /// device rejects), and both clean up independently without affecting each other — extends the
    /// existing <c>RelayServerTests.TwoIndependentSessions_ResolveIndependently_MultiPc</c> coverage
    /// (which drives the relay directly) up to the real <c>AuthWorker</c> orchestration layer.
    /// </summary>
    [Fact]
    public async Task RutaC_MultipleEligibleDevices_BothSessionsResolveAndCleanUpIndependently()
    {
        var tunnel = new FakeTunnelStatusProvider { IsConnected = true };
        var device1 = NewDevice(pushAuthEnabled: true, fcmTokenValid: true, fcmToken: "tok-1");
        var device2 = NewDevice(pushAuthEnabled: true, fcmTokenValid: true, fcmToken: "tok-2");
        RelayServer? relayRef = null;

        async Task OnChallengeSent(IDictionary<string, string> data)
        {
            var sessionId = data["session_id"];
            var deviceIdStr = data["device_id"];
            var deviceKey = deviceIdStr == device1.DeviceId.ToString() ? device1.DeviceKey : device2.DeviceKey;
            var relayKey = RelayKeyDerivation.DeriveRelayKey(deviceKey);
            var jwt = JwtHelper.CreateToken(deviceIdStr, sessionId, relayKey);
            using var http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{relayRef!.BoundPort}") };
            var resp = await http.PostAsJsonAsync("/api/auth/reject", new
            {
                session_id = sessionId,
                device_id = deviceIdStr,
                reason = "not_my_pc",
                jwt
            });
            resp.EnsureSuccessStatusCode();
        }

        var fcm = new FakeFcmPushSender(OnChallengeSent);
        var (worker, relay, _, db) = await BuildWorkerAsync(tunnel, globalTimeoutSeconds: 2, fcm: fcm);
        relayRef = relay;

        db.Devices.Add(device1);
        db.Devices.Add(device2);
        db.SaveChanges();

        var outcome = await worker.RunAuthRaceAsync(_ => Task.CompletedTask, CancellationToken.None);

        Assert.False(outcome.Success);
        Assert.Equal(2, fcm.Challenges.Count);
        foreach (var msg in fcm.Challenges)
            Assert.False(relay.TryGetSession(msg["session_id"], out _));
    }
}
