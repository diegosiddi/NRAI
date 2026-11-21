using System;
using System.IO;
using Nrai.Shell;
using Newtonsoft.Json.Linq;

namespace Nrai.Shell.Tests
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            if (args.Length != 1) throw new ArgumentException("Pass the tests/vectors/v1 directory.");
            var directory = args[0];
            var catalog = JObject.Parse(File.ReadAllText(Path.Combine(directory, "catalog.json")));
            foreach (var vector in (JArray)catalog["vectors"])
            {
                var file = (string)vector["file"];
                var expected = (string)vector["expected"];
                var bytes = File.ReadAllBytes(Path.Combine(directory, file));
                var accepted = true;
                try { ThumbnailProvider.VerifyAndGetPayloadForConformance(bytes); }
                catch { accepted = false; }
                if (accepted != (expected == "accept"))
                    throw new InvalidDataException("C# verifier mismatch for " + file);
            }
            Console.WriteLine("C# verifier accepted and rejected all NRAI v1 conformance vectors.");
            return 0;
        }
    }
}
