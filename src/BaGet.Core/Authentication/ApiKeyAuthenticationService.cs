using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace BaGet.Core
{
    public class ApiKeyAuthenticationService : IAuthenticationService
    {

        private readonly HashSet<byte[]> _validApiKeysHashed;
        private readonly bool _authenticationDisabled;


        public ApiKeyAuthenticationService(IOptionsSnapshot<BaGetOptions> options)
        {

            if (options == null) throw new ArgumentNullException(nameof(options));

            var apiKeySetting = options.Value.ApiKey;
            if (string.IsNullOrWhiteSpace(apiKeySetting))
            {
                _authenticationDisabled = true;
                _validApiKeysHashed = new HashSet<byte[]>(ByteEqualityComparer.Instance);
                return;
            }
            _authenticationDisabled = false;
            // 拆分、清理、去重，并预计算哈希值
            var keys = apiKeySetting
                .Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(k => k.Trim())
                .Where(k => !string.IsNullOrEmpty(k))
                .Distinct(StringComparer.Ordinal) // 去重
                .ToArray();


            if (keys.Length == 0)
            {
                _authenticationDisabled = true;
                _validApiKeysHashed = new HashSet<byte[]>(ByteEqualityComparer.Instance);
            }
            else
            {
                _validApiKeysHashed = new HashSet<byte[]>(
                    keys.Select(k => HashApiKey(k)),
                    ByteEqualityComparer.Instance
                );
            }

        }


        public Task<bool> AuthenticateAsync(string apiKey, CancellationToken cancellationToken = default)
        {

            if (_authenticationDisabled) return Task.FromResult(true);

            if (string.IsNullOrEmpty(apiKey))
                return Task.FromResult(false);

            var hash = HashApiKey(apiKey);
            return Task.FromResult(_validApiKeysHashed.Contains(hash));

        }


        // 使用 SHA256 对 API Key 哈希（不可逆，且固定长度）

        private static byte[] HashApiKey(string key)
        {

            using var sha256 = SHA256.Create();

            return sha256.ComputeHash(Encoding.UTF8.GetBytes(key));

        }


        // 自定义字节数组相等比较器（用于 HashSet）

        private sealed class ByteEqualityComparer : IEqualityComparer<byte[]>
        {

            public static readonly ByteEqualityComparer Instance = new();


            public bool Equals(byte[]? x, byte[]? y)
            {

                if (x == y) return true;

                if (x is null || y is null || x.Length != y.Length) return false;

                return CryptographicOperations.FixedTimeEquals(x, y);

            }


            public int GetHashCode(byte[] obj)

            {

                if (obj == null) return 0;

                // 简单哈希（不用于安全，仅用于分桶）

                return obj.Length > 0 ? obj[0] ^ obj[^1] : 0;

            }

        }

    }
}
