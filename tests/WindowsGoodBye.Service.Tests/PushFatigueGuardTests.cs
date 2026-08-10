using WindowsGoodBye.Service;
using Xunit;

namespace WindowsGoodBye.Service.Tests;

/// <summary>
/// Smoke tests for <see cref="PushFatigueGuard"/> (Fase 3 — docs/plan_push_auth_v2.md,
/// "🛡️ Defensa contra Push Fatigue", point 2). Drives the guard with a synthetic, monotonically
/// advancing clock instead of real time so the 8s/2min/10min/1h windows can be exercised quickly and
/// deterministically.
/// </summary>
public class PushFatigueGuardTests
{
    [Fact]
    public void FirstChallenge_IsAlwaysAllowed()
    {
        var guard = new PushFatigueGuard();
        var decision = guard.TryRecordChallenge(DateTimeOffset.UtcNow);

        Assert.True(decision.IsAllowed);
        Assert.Equal(1, decision.AttemptNumber);
    }

    [Fact]
    public void SecondChallenge_WithinMinInterval_IsDenied()
    {
        var guard = new PushFatigueGuard();
        var t0 = DateTimeOffset.UtcNow;

        Assert.True(guard.TryRecordChallenge(t0).IsAllowed);

        var decision = guard.TryRecordChallenge(t0.AddSeconds(3)); // < 8s minimum
        Assert.False(decision.IsAllowed);
        Assert.Equal(FatigueDenyReason.MinInterval, decision.DenyReason);
    }

    [Fact]
    public void SecondChallenge_AfterMinInterval_IsAllowed()
    {
        var guard = new PushFatigueGuard();
        var t0 = DateTimeOffset.UtcNow;

        Assert.True(guard.TryRecordChallenge(t0).IsAllowed);

        var decision = guard.TryRecordChallenge(t0 + PushFatigueGuard.MinInterval + TimeSpan.FromMilliseconds(1));
        Assert.True(decision.IsAllowed);
        Assert.Equal(2, decision.AttemptNumber);
    }

    [Fact]
    public void ThirdAttemptWithin2Minutes_TriggersSoftBackoff()
    {
        var guard = new PushFatigueGuard();
        var t = DateTimeOffset.UtcNow;
        var step = PushFatigueGuard.MinInterval + TimeSpan.FromSeconds(1);

        Assert.True(guard.TryRecordChallenge(t).IsAllowed); t += step;
        Assert.True(guard.TryRecordChallenge(t).IsAllowed); t += step;
        var third = guard.TryRecordChallenge(t); // 3rd within 2 minutes -> backoff engaged for the NEXT one
        Assert.True(third.IsAllowed);
        Assert.Equal(3, third.AttemptNumber);

        t += step;
        var fourth = guard.TryRecordChallenge(t);
        Assert.False(fourth.IsAllowed);
        Assert.Equal(FatigueDenyReason.BackoffActive, fourth.DenyReason);

        // After the 30s soft backoff elapses, a new attempt is allowed again.
        var afterBackoff = guard.TryRecordChallenge(t + PushFatigueGuard.SoftLimitBackoff + TimeSpan.FromMilliseconds(1));
        Assert.True(afterBackoff.IsAllowed);
    }

    [Fact]
    public void SixthAttemptWithin10Minutes_TriggersHardBackoff()
    {
        var guard = new PushFatigueGuard();
        var t = DateTimeOffset.UtcNow;
        // Space attempts >30s apart so the soft (3/2min) backoff never blocks us before we reach 6.
        var step = TimeSpan.FromSeconds(31);

        for (int i = 0; i < 6; i++)
        {
            var decision = guard.TryRecordChallenge(t);
            Assert.True(decision.IsAllowed, $"attempt {i + 1} should be allowed");
            t += step;
        }

        var seventh = guard.TryRecordChallenge(t);
        Assert.False(seventh.IsAllowed);
        Assert.Equal(FatigueDenyReason.BackoffActive, seventh.DenyReason);

        var afterHardBackoff = guard.TryRecordChallenge(t + PushFatigueGuard.HardLimitBackoff + TimeSpan.FromMilliseconds(1));
        Assert.True(afterHardBackoff.IsAllowed);
    }

    [Fact]
    public void EleventhAttemptWithinAnHour_HitsHardCap()
    {
        var guard = new PushFatigueGuard();
        var t = DateTimeOffset.UtcNow;

        // 3-minute spacing keeps every trailing 2-minute window at 0 prior entries and every trailing
        // 10-minute window at ~3 prior entries — well clear of the soft (3/2min) and hard (6/10min)
        // backoff thresholds — while still landing all 10 attempts comfortably inside the 1-hour
        // window (27 minutes total), so only the raw 10/hour cap is what denies the 11th attempt.
        var step = TimeSpan.FromMinutes(3);
        for (int i = 0; i < PushFatigueGuard.MaxPerHour; i++)
        {
            var decision = guard.TryRecordChallenge(t);
            Assert.True(decision.IsAllowed, $"attempt {i + 1} should be allowed");
            Assert.Null(decision.DenyReason);
            t += step;
        }

        var overCap = guard.TryRecordChallenge(t);
        Assert.False(overCap.IsAllowed);
        Assert.Equal(FatigueDenyReason.HardCapPerHour, overCap.DenyReason);
    }

    [Fact]
    public void Reset_ClearsHistoryAndBackoff()
    {
        var guard = new PushFatigueGuard();
        var t = DateTimeOffset.UtcNow;

        Assert.True(guard.TryRecordChallenge(t).IsAllowed);
        guard.Reset();

        // Immediately after reset, even a challenge within what would have been the min-interval
        // window is allowed again (history is empty).
        var decision = guard.TryRecordChallenge(t.AddSeconds(1));
        Assert.True(decision.IsAllowed);
        Assert.Equal(1, decision.AttemptNumber);
    }
}
