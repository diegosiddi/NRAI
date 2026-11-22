using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Nrai.Shell
{
    [ComVisible(true)]
    [Guid(ClassId)]
    [ClassInterface(ClassInterfaceType.None)]
    public sealed class ThumbnailProvider : IInitializeWithStream, IThumbnailProvider
    {
        public const string ClassId = "721a6e9a-74f8-4a43-bfa7-79a6fef1d622";
        private const int MaxManifestBytes = 4 * 1024 * 1024;
        private const int MaxPreviewFileBytes = 256 * 1024 * 1024;
        private const string ThumbnailHandlerCategory = "E357FCCD-A995-4576-B01F-234630154E96";
        private const string Magic = "NRAI\r\n\x1a\n";
        private static readonly string[] RightsKeys = {
            "ai_training", "ai_finetuning", "ai_inference", "ai_analysis", "screenshot", "redistribution"
        };
        private static readonly string[] RightsValues = { "allow", "deny", "ask", "unspecified" };
        private byte[] _container;

        public void Initialize(IStream stream, int mode)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            using (var output = new MemoryStream())
            {
                var buffer = new byte[64 * 1024];
                var readCount = Marshal.AllocCoTaskMem(sizeof(int));
                try
                {
                    while (true)
                    {
                        stream.Read(buffer, buffer.Length, readCount);
                        var count = Marshal.ReadInt32(readCount);
                        if (count <= 0) break;
                        if (output.Length + count > MaxPreviewFileBytes)
                            throw new InvalidDataException("NRAI preview exceeds the 256 MiB thumbnail limit.");
                        output.Write(buffer, 0, count);
                    }
                }
                finally { Marshal.FreeCoTaskMem(readCount); }
                _container = output.ToArray();
            }
        }

        public void GetThumbnail(uint requestedSize, out IntPtr thumbnail, out WtsAlphaType alphaType)
        {
            thumbnail = IntPtr.Zero;
            alphaType = WtsAlphaType.Unknown;
            if (_container == null || requestedSize == 0 || requestedSize > 2048)
                throw new InvalidDataException("Invalid NRAI thumbnail request.");

            var payload = VerifyAndGetPayload(_container, suppressDeniedThumbnail: true);
            using (var input = new MemoryStream(payload, writable: false))
            using (var source = Image.FromStream(input, useEmbeddedColorManagement: true, validateImageData: true))
            {
                var scale = Math.Min((double)requestedSize / source.Width, (double)requestedSize / source.Height);
                var width = Math.Max(1, (int)Math.Round(source.Width * scale));
                var height = Math.Max(1, (int)Math.Round(source.Height * scale));
                using (var bitmap = new Bitmap(width, height, PixelFormat.Format32bppArgb))
                using (var graphics = Graphics.FromImage(bitmap))
                {
                    graphics.Clear(Color.Transparent);
                    graphics.InterpolationMode = InterpolationMode.HighQualityBicubic;
                    graphics.DrawImage(source, new Rectangle(0, 0, width, height));
                    thumbnail = bitmap.GetHbitmap(Color.Transparent);
                    alphaType = WtsAlphaType.Argb;
                }
            }
        }

        public static byte[] VerifyAndGetPayloadForConformance(byte[] bytes)
        {
            return VerifyAndGetPayload(bytes, suppressDeniedThumbnail: false);
        }

        private static byte[] VerifyAndGetPayload(byte[] bytes, bool suppressDeniedThumbnail)
        {
            if (bytes.Length < 16 || !Encoding.ASCII.GetBytes(Magic).SequenceEqual(bytes.Take(8)))
                throw new InvalidDataException("Not an NRAI v1 container.");
            ulong manifestLength = 0;
            for (var i = 8; i < 16; i++) manifestLength = (manifestLength << 8) | bytes[i];
            if (manifestLength > MaxManifestBytes) throw new InvalidDataException("NRAI manifest exceeds 4 MiB.");
            var payloadStart = 16L + (long)manifestLength;
            if (payloadStart > bytes.Length) throw new InvalidDataException("Truncated NRAI manifest.");

            var manifestBytes = new byte[(int)manifestLength];
            Buffer.BlockCopy(bytes, 16, manifestBytes, 0, manifestBytes.Length);
            if (manifestBytes.Length >= 3 && manifestBytes[0] == 0xef && manifestBytes[1] == 0xbb && manifestBytes[2] == 0xbf)
                throw new InvalidDataException("UTF-8 BOM is not allowed in NRAI manifest JSON.");
            var manifestText = new UTF8Encoding(false, true).GetString(manifestBytes);
            JObject manifest;
            using (var reader = new JsonTextReader(new StringReader(manifestText))
            {
                DateParseHandling = DateParseHandling.None,
                FloatParseHandling = FloatParseHandling.Decimal,
                MaxDepth = 64
            })
            {
                manifest = JObject.Load(reader, new JsonLoadSettings
                {
                    DuplicatePropertyNameHandling = DuplicatePropertyNameHandling.Error,
                CommentHandling = CommentHandling.Load,
                    LineInfoHandling = LineInfoHandling.Ignore
                });
                if (reader.Read()) throw new InvalidDataException("Unexpected data after NRAI manifest JSON.");
            }
            if (manifest.DescendantsAndSelf().Any(token => token.Type == JTokenType.Comment))
                throw new InvalidDataException("Comments are not allowed in NRAI JSON.");

            ValidateManifest(manifest);
            if (manifest.Property("encryption") != null)
                throw new InvalidDataException("Encrypted NRAI payloads are not rendered as Explorer thumbnails.");
            var payload = new byte[bytes.Length - (int)payloadStart];
            Buffer.BlockCopy(bytes, (int)payloadStart, payload, 0, payload.Length);
            var payloadInfo = (JObject)manifest["payload"];
            if ((ulong)payload.Length != (ulong)payloadInfo["length"])
                throw new InvalidDataException("NRAI payload length mismatch.");
            string digest;
            using (var sha = SHA256.Create()) digest = Hex(sha.ComputeHash(payload));
            if (!String.Equals(digest, (string)payloadInfo["sha256"], StringComparison.Ordinal))
                throw new InvalidDataException("NRAI payload digest mismatch.");

            var signature = (JObject)manifest["signature"];
            var rawKey = DecodeBase64((string)signature["public_key"]);
            var signatureBytes = DecodeBase64((string)signature["value"]);
            if (rawKey.Length != 32 || signatureBytes.Length != 64)
                throw new InvalidDataException("NRAI signature has invalid lengths.");
            using (var sha = SHA256.Create())
            {
                var keyId = Hex(sha.ComputeHash(rawKey).Take(16).ToArray());
                if (!String.Equals(keyId, (string)signature["key_id"], StringComparison.Ordinal))
                    throw new InvalidDataException("NRAI signing key id does not match.");
            }

            var unsignedManifest = (JObject)manifest.DeepClone();
            unsignedManifest.Remove("signature");
            var signedBytes = Encoding.UTF8.GetBytes(CanonicalJson(unsignedManifest));
            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(rawKey, 0));
            verifier.BlockUpdate(signedBytes, 0, signedBytes.Length);
            if (!verifier.VerifySignature(signatureBytes)) throw new InvalidDataException("NRAI signature invalid.");

            var rights = (JObject)manifest["rights"];
            if (suppressDeniedThumbnail && (string)rights["screenshot"] == "deny")
                throw new InvalidDataException("NRAI screenshot policy is deny; thumbnail suppressed.");
            return payload;
        }

        private static void ValidateManifest(JObject manifest)
        {
            if ((string)manifest["format"] != "NRAI" || (int?)manifest["version"] != 1)
                throw new InvalidDataException("Unsupported NRAI format version.");
            if (!Guid.TryParse((string)manifest["asset_id"], out var assetId) ||
                !String.Equals(assetId.ToString("D"), (string)manifest["asset_id"], StringComparison.Ordinal))
                throw new InvalidDataException("Invalid NRAI asset_id.");
            if (!IsUtcTimestamp((string)manifest["created_at"])) throw new InvalidDataException("Invalid NRAI created_at.");
            var mediaType = (string)manifest["media_type"];
            if (String.IsNullOrEmpty(mediaType) || !Regex.IsMatch(mediaType, @"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$"))
                throw new InvalidDataException("Invalid NRAI media_type.");
            var payload = manifest["payload"] as JObject;
            if (payload == null || payload["length"]?.Type != JTokenType.Integer ||
                payload["length"].Value<long>() < 0 || !Regex.IsMatch((string)payload["sha256"] ?? "", "^[0-9a-f]{64}$"))
                throw new InvalidDataException("Invalid NRAI payload descriptor.");
            var rights = manifest["rights"] as JObject;
            if (rights == null || !RightsKeys.OrderBy(x => x).SequenceEqual(rights.Properties().Select(p => p.Name).OrderBy(x => x)) ||
                rights.Properties().Any(p => p.Value.Type != JTokenType.String || !RightsValues.Contains((string)p.Value)))
                throw new InvalidDataException("Invalid NRAI rights object.");
            if (manifest["creator"] != null && manifest["creator"].Type != JTokenType.String)
                throw new InvalidDataException("Invalid NRAI creator field.");
            if (manifest["lineage"] != null)
            {
                var lineage = manifest["lineage"] as JObject;
                var expected = new[] { "operation", "parent_asset_id", "parent_payload_sha256", "recorded_at" };
                if (lineage == null || !expected.SequenceEqual(lineage.Properties().Select(p => p.Name).OrderBy(x => x)) ||
                    !Guid.TryParse((string)lineage["parent_asset_id"], out var parentId) ||
                    !String.Equals(parentId.ToString("D"), (string)lineage["parent_asset_id"], StringComparison.Ordinal) ||
                    !Regex.IsMatch((string)lineage["parent_payload_sha256"] ?? "", "^[0-9a-f]{64}$") ||
                    String.IsNullOrEmpty((string)lineage["operation"]) || !IsUtcTimestamp((string)lineage["recorded_at"]))
                    throw new InvalidDataException("Invalid NRAI lineage object.");
            }
            var signature = manifest["signature"] as JObject;
            var signatureKeys = new[] { "algorithm", "key_id", "public_key", "value" };
            if (signature == null || !signatureKeys.OrderBy(x => x).SequenceEqual(signature.Properties().Select(p => p.Name).OrderBy(x => x)) ||
                (string)signature["algorithm"] != "Ed25519" || !Regex.IsMatch((string)signature["key_id"] ?? "", "^[0-9a-f]{32}$") ||
                signature["public_key"].Type != JTokenType.String || signature["value"].Type != JTokenType.String)
                throw new InvalidDataException("Invalid NRAI signature object.");
            _ = CanonicalJson(manifest);
        }

        private static bool IsUtcTimestamp(string value)
        {
            return value != null && value.EndsWith("Z", StringComparison.Ordinal) &&
                DateTimeOffset.TryParseExact(value, "yyyy-MM-dd'T'HH:mm:ss'Z'",
                    CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out _);
        }

        private static string CanonicalJson(JToken token)
        {
            if (token is JObject obj)
                return "{" + String.Join(",", obj.Properties().OrderBy(p => p.Name, Utf8StringComparer.Instance)
                    .Select(p => Quote(p.Name) + ":" + CanonicalJson(p.Value))) + "}";
            if (token is JArray array)
                return "[" + String.Join(",", array.Select(CanonicalJson)) + "]";
            if (token is JValue value)
            {
                switch (value.Type)
                {
                    case JTokenType.String: return Quote((string)value);
                    case JTokenType.Integer: {
                        var integer = BigInteger.Parse(Convert.ToString(value.Value, CultureInfo.InvariantCulture), CultureInfo.InvariantCulture);
                        if (integer < BigInteger.Parse("-9223372036854775808", CultureInfo.InvariantCulture) ||
                            integer > BigInteger.Parse("18446744073709551615", CultureInfo.InvariantCulture))
                            throw new InvalidDataException("NRAI JSON integer is outside the supported 64-bit range.");
                        return integer.ToString(CultureInfo.InvariantCulture);
                    }
                    case JTokenType.Boolean: return (bool)value ? "true" : "false";
                    case JTokenType.Null: return "null";
                    default: throw new InvalidDataException("Unsupported JSON value in NRAI v1 canonicalization.");
                }
            }
            throw new InvalidDataException("Unsupported JSON value in NRAI v1 canonicalization.");
        }

        private static string Quote(string value)
        {
            var output = new StringBuilder("\"");
            for (var index = 0; index < value.Length; index++)
            {
                var c = value[index];
                if (Char.IsHighSurrogate(c))
                {
                    if (index + 1 >= value.Length || !Char.IsLowSurrogate(value[index + 1]))
                        throw new InvalidDataException("Unpaired Unicode surrogate in NRAI JSON.");
                    output.Append(c).Append(value[++index]);
                    continue;
                }
                if (Char.IsLowSurrogate(c)) throw new InvalidDataException("Unpaired Unicode surrogate in NRAI JSON.");
                switch (c)
                {
                    case '"': output.Append("\\\""); break;
                    case '\\': output.Append("\\\\"); break;
                    case '\b': output.Append("\\b"); break;
                    case '\t': output.Append("\\t"); break;
                    case '\n': output.Append("\\n"); break;
                    case '\f': output.Append("\\f"); break;
                    case '\r': output.Append("\\r"); break;
                    default:
                        if (c < 0x20) output.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        else output.Append(c);
                        break;
                }
            }
            return output.Append('"').ToString();
        }

        private static byte[] DecodeBase64(string value)
        {
            var decoded = Convert.FromBase64String(value);
            if (!String.Equals(Convert.ToBase64String(decoded), value, StringComparison.Ordinal))
                throw new InvalidDataException("Non-canonical base64 in NRAI signature.");
            return decoded;
        }

        private static string Hex(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }

        private sealed class Utf8StringComparer : System.Collections.Generic.IComparer<string>
        {
            public static readonly Utf8StringComparer Instance = new Utf8StringComparer();
            public int Compare(string left, string right)
            {
                var a = Encoding.UTF8.GetBytes(left);
                var b = Encoding.UTF8.GetBytes(right);
                var common = Math.Min(a.Length, b.Length);
                for (var i = 0; i < common; i++) if (a[i] != b[i]) return a[i].CompareTo(b[i]);
                return a.Length.CompareTo(b.Length);
            }
        }
    }

    [ComVisible(true)]
    [Guid("B824B49D-22AC-4161-AC8A-9916E8FA3F7F")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IInitializeWithStream
    {
        void Initialize([In, MarshalAs(UnmanagedType.Interface)] IStream stream, int mode);
    }

    [ComVisible(true)]
    [Guid("E357FCCD-A995-4576-B01F-234630154E96")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IThumbnailProvider
    {
        void GetThumbnail(uint requestedSize, out IntPtr thumbnail, out WtsAlphaType alphaType);
    }

    public enum WtsAlphaType
    {
        Unknown = 0,
        Rgb = 1,
        Argb = 2
    }
}
