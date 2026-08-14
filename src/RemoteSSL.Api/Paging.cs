using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace RemoteSSL.Api;

/// <summary>
/// The one pagination shape every list endpoint uses (design doc §27.2: "Pagination/filter/sort
/// standartlaştırılmalı").
///
/// The page is returned as a plain array with the total in an <c>X-Total-Count</c> header rather
/// than wrapped in an envelope. That keeps every existing caller working — the body's shape does
/// not change — while giving a client what it needs to page: how many rows there are in total.
/// </summary>
public sealed record PageRequest
{
    /// <summary>Rows to skip. Negative values are treated as zero rather than refused.</summary>
    [FromQuery(Name = "skip")]
    public int Skip { get; init; }

    /// <summary>
    /// Rows to return. Defaults to the historical cap so an existing caller that passes nothing
    /// sees exactly what it saw before.
    /// </summary>
    [FromQuery(Name = "take")]
    public int? Take { get; init; }

    public const int DefaultTake = 100;

    /// <summary>
    /// Hard ceiling. A list endpoint is reachable by anyone who can read, so an unbounded take is
    /// a cheap way to pull the whole table in one request.
    /// </summary>
    public const int MaxTake = 500;

    public int EffectiveSkip => Math.Max(0, Skip);
    public int EffectiveTake => Math.Clamp(Take ?? DefaultTake, 1, MaxTake);
}

public static class PagingExtensions
{
    public const string TotalCountHeader = "X-Total-Count";

    /// <summary>
    /// Counts the query, records the total on the response and returns the requested page.
    /// The count runs against the same filtered query, so the total describes what the caller
    /// asked for rather than the whole table.
    /// </summary>
    public static async Task<List<T>> ToPageAsync<T>(
        this IQueryable<T> query, PageRequest page, HttpResponse response, CancellationToken ct)
    {
        var total = await query.CountAsync(ct);
        response.Headers[TotalCountHeader] = total.ToString();

        return await query.Skip(page.EffectiveSkip).Take(page.EffectiveTake).ToListAsync(ct);
    }
}
