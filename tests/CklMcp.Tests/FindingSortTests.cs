using CklViewer.Models;
using Xunit;

namespace CklViewer.Tests;

public class FindingSortTests
{
    [Theory]
    [InlineData(FindingStatus.Open, 0)]
    [InlineData(FindingStatus.NotReviewed, 1)]
    [InlineData(FindingStatus.NotAFinding, 2)]
    [InlineData(FindingStatus.NotApplicable, 3)]
    public void StatusSortOrder_RanksOpenFirst(FindingStatus status, int expected) =>
        Assert.Equal(expected, new Vulnerability { Status = status }.StatusSortOrder);

    [Fact]
    public void SortingByStatusOrder_BringsActionableFindingsToTop()
    {
        var ordered = new[]
            {
                FindingStatus.NotApplicable,
                FindingStatus.NotAFinding,
                FindingStatus.Open,
                FindingStatus.NotReviewed
            }
            .Select(s => new Vulnerability { Status = s })
            .OrderBy(v => v.StatusSortOrder)
            .Select(v => v.Status)
            .ToArray();

        Assert.Equal(new[]
        {
            FindingStatus.Open,
            FindingStatus.NotReviewed,
            FindingStatus.NotAFinding,
            FindingStatus.NotApplicable
        }, ordered);
    }
}
