namespace Vesper.Cli;

public static class DockerMountArguments
{
    public static string Bind(string source, string target, bool readOnly = false)
    {
        return $"type=bind,source={source},target={target}{(readOnly ? ",readonly" : "")}";
    }

    public static string Volume(string source, string target, bool readOnly = false)
    {
        return $"type=volume,source={source},target={target}{(readOnly ? ",readonly" : "")}";
    }
}