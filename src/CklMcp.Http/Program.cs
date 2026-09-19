using CklMcp.Http;
using CklMcp.Tools;

if (args.Contains("-h") || args.Contains("--help"))
{
    Console.WriteLine(HttpOptions.Usage);
    return 0;
}

try
{
    var server = ServerOptions.Parse(args);
    var http = HttpOptions.Parse(args, server);

    var app = await HttpHost.StartAsync(http, server);
    foreach (var line in HttpHost.BannerLines(app, http, server))
    {
        Console.Error.WriteLine(line);
    }

    await app.WaitForShutdownAsync();
    return 0;
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine($"error: {ex.Message}");
    Console.Error.WriteLine("Run with --help for usage.");
    return 2;
}
