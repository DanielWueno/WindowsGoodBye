namespace WindowsGoodBye.Service;

/// <summary>Result of one leg (Ruta A/B/C) of <see cref="AuthWorker.RunAuthRaceAsync"/>.</summary>
public readonly record struct AuthRaceOutcome(bool Success, string? DeviceName = null, string? Route = null);

/// <summary>
/// The actual "first SUCCESS wins" combinator behind docs/plan_push_auth_v2.md's
/// "🔄 Algoritmo de Decisión del Modo Hybrid" (<c>Task.WhenAny(rutas[])</c> + "PRIMERO QUE RESPONDE").
///
/// Deliberately NOT a plain <c>Task.WhenAny</c>: the first task to *complete* is not necessarily the
/// first to *succeed* (e.g. a fast direct-transport probe might finish quickly with "no one answered"
/// while a slower push-auth round trip is still pending and eventually succeeds). This drains
/// completed-but-failed legs and keeps waiting until either a success arrives or every leg is
/// exhausted — callers are expected to bound the overall wait via cancellation (the 60s global timeout)
/// so a stuck leg can't hang this forever.
///
/// Factored out as a small, pure, dependency-free method specifically so it can be unit-tested in
/// isolation (see tests/WindowsGoodBye.Service.Tests) without standing up real transports/FCM/relay.
/// </summary>
public static class AuthRaceCombinator
{
    public static async Task<AuthRaceOutcome> RunAsync(List<Task<AuthRaceOutcome>> legs)
    {
        while (legs.Count > 0)
        {
            var completed = await Task.WhenAny(legs).ConfigureAwait(false);
            legs.Remove(completed);

            AuthRaceOutcome outcome;
            try
            {
                outcome = await completed.ConfigureAwait(false);
            }
            catch
            {
                // A leg faulting (exception) counts as "that leg failed", not a race-ending error —
                // other legs (or the eventual timeout) still get to decide the overall outcome.
                outcome = new AuthRaceOutcome(false);
            }

            if (outcome.Success)
                return outcome;
        }

        return new AuthRaceOutcome(false);
    }
}
