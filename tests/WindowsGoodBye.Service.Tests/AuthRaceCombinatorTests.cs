using WindowsGoodBye.Service;
using Xunit;

namespace WindowsGoodBye.Service.Tests;

/// <summary>
/// Tests the "first SUCCESS wins" race combinator behind <c>AuthWorker.RunAuthRaceAsync</c> (Fase 3 —
/// docs/plan_push_auth_v2.md, "🔄 Algoritmo de Decisión del Modo Hybrid") in isolation, using
/// hand-crafted tasks instead of real transports/FCM/relay. Covers: Ruta A (fast leg) winning, Ruta C
/// (slower leg) winning after a faster leg fails, and a full timeout when every leg fails.
/// </summary>
public class AuthRaceCombinatorTests
{
    [Fact]
    public async Task FasterSuccessfulLeg_WinsImmediately()
    {
        var fastWin = Task.FromResult(new AuthRaceOutcome(true, "Pixel 7", "A"));
        var slowWin = Delayed(TimeSpan.FromMilliseconds(200), new AuthRaceOutcome(true, "Pixel 7", "C"));

        var result = await AuthRaceCombinator.RunAsync(new List<Task<AuthRaceOutcome>> { fastWin, slowWin });

        Assert.True(result.Success);
        Assert.Equal("A", result.Route);
    }

    [Fact]
    public async Task FastFailure_DoesNotWin_SlowerSuccessDoes()
    {
        // Simulates Ruta A completing quickly with "no direct transport answered" while Ruta C
        // (push-auth round trip) is still pending and eventually succeeds.
        var fastFail = Delayed(TimeSpan.FromMilliseconds(10), new AuthRaceOutcome(false, Route: "A"));
        var slowSuccess = Delayed(TimeSpan.FromMilliseconds(100), new AuthRaceOutcome(true, "Galaxy S24", "C"));

        var result = await AuthRaceCombinator.RunAsync(new List<Task<AuthRaceOutcome>> { fastFail, slowSuccess });

        Assert.True(result.Success);
        Assert.Equal("C", result.Route);
        Assert.Equal("Galaxy S24", result.DeviceName);
    }

    [Fact]
    public async Task AllLegsFail_ResultIsFailure()
    {
        var a = Delayed(TimeSpan.FromMilliseconds(5), new AuthRaceOutcome(false, Route: "A"));
        var b = Delayed(TimeSpan.FromMilliseconds(10), new AuthRaceOutcome(false, Route: "B"));
        var c = Delayed(TimeSpan.FromMilliseconds(15), new AuthRaceOutcome(false, Route: "C"));

        var result = await AuthRaceCombinator.RunAsync(new List<Task<AuthRaceOutcome>> { a, b, c });

        Assert.False(result.Success);
    }

    [Fact]
    public async Task EmptyLegList_ResultIsFailure()
    {
        var result = await AuthRaceCombinator.RunAsync(new List<Task<AuthRaceOutcome>>());
        Assert.False(result.Success);
    }

    [Fact]
    public async Task FaultedLeg_IsTreatedAsFailure_NotAsRaceEndingException()
    {
        var faulted = Task.Run<AuthRaceOutcome>(AuthRaceOutcome () => throw new InvalidOperationException("simulated relay error"));
        var eventualSuccess = Delayed(TimeSpan.FromMilliseconds(50), new AuthRaceOutcome(true, "Pixel 7", "C"));

        var result = await AuthRaceCombinator.RunAsync(new List<Task<AuthRaceOutcome>> { faulted, eventualSuccess });

        Assert.True(result.Success);
        Assert.Equal("C", result.Route);
    }

    private static async Task<AuthRaceOutcome> Delayed(TimeSpan delay, AuthRaceOutcome outcome)
    {
        await Task.Delay(delay);
        return outcome;
    }
}
