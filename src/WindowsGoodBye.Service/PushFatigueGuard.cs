namespace WindowsGoodBye.Service;

/// <summary>
/// Rate-limits how often <see cref="AuthWorker"/> is allowed to generate a NEW push-auth challenge
/// cycle (nonce + display_code + session(s)) for a single CP login session — this is the "lado PC"
/// defense from docs/plan_push_auth_v2.md, "🛡️ Defensa contra Push Fatigue", point 2. It is
/// deliberately independent from the relay's per-IP/per-device_id rate limiting (<see cref="RelayLimits"/>):
/// that protects the *process* from network abuse; this protects the *user* from prompt-bombing, and
/// per the plan must apply "incluso si Ruta A/B ... es la que dispara los intentos, no solo Ruta C" —
/// i.e. it gates the whole <c>RunAuthRaceAsync</c> cycle, not just the relay/push leg, because Ruta A/B
/// can also repeatedly ping the phone (auth_discover -> auth_alive -> auth_req triggers a fingerprint
/// prompt on Android too).
///
/// Exact thresholds (from the plan's table):
/// <list type="bullet">
/// <item><description>Minimum 8s between challenges.</description></item>
/// <item><description>3 attempts in 2 minutes -> +30s mandatory backoff before the next one.</description></item>
/// <item><description>6 attempts in 10 minutes -> +5 minutes mandatory backoff (CP should show a
/// "too many attempts, use your password" banner).</description></item>
/// <item><description>Hard cap: 10 challenges/hour -> password only.</description></item>
/// </list>
///
/// Implementation note: the plan describes the hard cap as lasting "hasta reinicio de la pantalla de
/// bloqueo". This class doesn't have a hook into the Windows lock/unlock lifecycle, so instead it
/// relies on (a) the sliding one-hour window naturally forgetting old attempts, and (b) an explicit
/// <see cref="Reset"/> call from <c>AuthWorker</c> whenever authentication actually succeeds (which is
/// the natural "end of this locked session" signal available to us). This is a deliberate, documented
/// interpretation — see docs/implementation_progress_push_auth_v2.md, Fase 3 notes.
/// </summary>
public sealed class PushFatigueGuard
{
    public static readonly TimeSpan MinInterval = TimeSpan.FromSeconds(8);

    public const int SoftLimitCount = 3;
    public static readonly TimeSpan SoftLimitWindow = TimeSpan.FromMinutes(2);
    public static readonly TimeSpan SoftLimitBackoff = TimeSpan.FromSeconds(30);

    public const int HardLimitCount = 6;
    public static readonly TimeSpan HardLimitWindow = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan HardLimitBackoff = TimeSpan.FromMinutes(5);

    public const int MaxPerHour = 10;
    public static readonly TimeSpan HourWindow = TimeSpan.FromHours(1);

    private readonly object _lock = new();
    private readonly List<DateTimeOffset> _history = new();
    private DateTimeOffset? _blockedUntil;

    /// <summary>
    /// Attempt to record a new challenge-generation event at <paramref name="now"/>. Returns whether
    /// it's allowed and, if so, the 1-based attempt number within the trailing 2-minute window (used
    /// as the "3er intento en los últimos 2 minutos" context shown to the user).
    /// </summary>
    public FatigueDecision TryRecordChallenge(DateTimeOffset now)
    {
        lock (_lock)
        {
            _history.RemoveAll(t => now - t > HourWindow);

            if (_blockedUntil is { } blockedUntil && now < blockedUntil)
                return FatigueDecision.Denied(FatigueDenyReason.BackoffActive, blockedUntil);

            if (_history.Count >= MaxPerHour)
                return FatigueDecision.Denied(FatigueDenyReason.HardCapPerHour, now.Add(HourWindow));

            if (_history.Count > 0 && now - _history[^1] < MinInterval)
                return FatigueDecision.Denied(FatigueDenyReason.MinInterval, _history[^1].Add(MinInterval));

            var countLast2Min = _history.Count(t => now - t <= SoftLimitWindow);
            var countLast10Min = _history.Count(t => now - t <= HardLimitWindow);

            _history.Add(now);
            var attemptNumberIn2Min = countLast2Min + 1;

            // Most severe threshold wins (they're mutually exclusive in strength: 5min > 30s).
            if (countLast10Min + 1 >= HardLimitCount)
                _blockedUntil = now.Add(HardLimitBackoff);
            else if (countLast2Min + 1 >= SoftLimitCount)
                _blockedUntil = now.Add(SoftLimitBackoff);

            return FatigueDecision.Allowed(attemptNumberIn2Min);
        }
    }

    /// <summary>Call when authentication succeeds via any route — see class remarks on the hard-cap semantics.</summary>
    public void Reset()
    {
        lock (_lock)
        {
            _history.Clear();
            _blockedUntil = null;
        }
    }
}

public enum FatigueDenyReason
{
    MinInterval,
    BackoffActive,
    HardCapPerHour
}

public readonly struct FatigueDecision
{
    public bool IsAllowed { get; }
    public int AttemptNumber { get; }
    public FatigueDenyReason? DenyReason { get; }
    public DateTimeOffset? RetryAfter { get; }

    private FatigueDecision(bool allowed, int attemptNumber, FatigueDenyReason? denyReason, DateTimeOffset? retryAfter)
    {
        IsAllowed = allowed;
        AttemptNumber = attemptNumber;
        DenyReason = denyReason;
        RetryAfter = retryAfter;
    }

    public static FatigueDecision Allowed(int attemptNumber) => new(true, attemptNumber, null, null);
    public static FatigueDecision Denied(FatigueDenyReason reason, DateTimeOffset retryAfter) =>
        new(false, 0, reason, retryAfter);
}
