// Copyright (C) 2025, Duplicati Inc.
// https://duplicati.com, hello@duplicati.com
// 
// Permission is hereby granted, free of charge, to any person obtaining a 
// copy of this software and associated documentation files (the "Software"), 
// to deal in the Software without restriction, including without limitation 
// the rights to use, copy, modify, merge, publish, distribute, sublicense, 
// and/or sell copies of the Software, and to permit persons to whom the 
// Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in 
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
// DEALINGS IN THE SOFTWARE.

using System.Security.Cryptography;

namespace JsonSignature.Tests;

public class JSONSignatureTests
{
    private static (string PublicKey, string PrivateKey) GenerateRsaKeys()
    {
        using var rsa = new RSACryptoServiceProvider(2048);
        var publicKey = rsa.ToXmlString(false);
        var privateKey = rsa.ToXmlString(true);
        return (publicKey, privateKey);
    }

    [Fact]
    public async Task SignAsync_SingleKey_ShouldSignAndVerify()
    {
        var (publicKey, privateKey) = GenerateRsaKeys();
        var data = "Hello, World!"u8.ToArray();
        using var source = new MemoryStream(data);
        using var target = new MemoryStream();

        var signOp = new JSONSignature.SignOperation(JSONSignature.RSA_SHA256, publicKey, privateKey);

        await JSONSignature.SignAsync(source, target, [signOp]);

        target.Position = 0;
        var verifyOp = new JSONSignature.VerifyOperation(JSONSignature.RSA_SHA256, publicKey);
        var matches = JSONSignature.Verify(target, [verifyOp]);

        Assert.Single(matches);
        Assert.Equal(JSONSignature.RSA_SHA256, matches.First().Algorithm);
        Assert.Equal(publicKey, matches.First().PublicKey);
    }

    [Fact]
    public async Task SignAsync_MultipleKeys_ShouldSignAndVerify()
    {
        var key1 = GenerateRsaKeys();
        var key2 = GenerateRsaKeys();
        var data = "Test data"u8.ToArray();
        using var source = new MemoryStream(data);
        using var target = new MemoryStream();

        var signOps = new[]
        {
            new JSONSignature.SignOperation(JSONSignature.RSA_SHA256, key1.PublicKey, key1.PrivateKey),
            new JSONSignature.SignOperation(JSONSignature.RSA_SHA256, key2.PublicKey, key2.PrivateKey)
        };

        await JSONSignature.SignAsync(source, target, signOps);

        target.Position = 0;
        var verifyOps = new[]
        {
            new JSONSignature.VerifyOperation(JSONSignature.RSA_SHA256, key1.PublicKey),
            new JSONSignature.VerifyOperation(JSONSignature.RSA_SHA256, key2.PublicKey)
        };
        var matches = JSONSignature.Verify(target, verifyOps);

        Assert.Equal(2, matches.Count());
    }

    [Fact]
    public async Task SignAsync_AlreadySigned_ShouldThrowException()
    {
        var (publicKey, privateKey) = GenerateRsaKeys();
        var data = "//SIGJSON"u8.ToArray();
        using var source = new MemoryStream(data);
        using var target = new MemoryStream();

        var signOp = new JSONSignature.SignOperation(JSONSignature.RSA_SHA256, publicKey, privateKey);

        await Assert.ThrowsAsync<Exception>(() => JSONSignature.SignAsync(source, target, [signOp]));
    }

    [Fact]
    public async Task SignAsync_NoSignOperations_ShouldThrowException()
    {
        var data = "Data"u8.ToArray();
        using var source = new MemoryStream(data);
        using var target = new MemoryStream();

        await Assert.ThrowsAsync<InvalidOperationException>(() => JSONSignature.SignAsync(source, target, []));
    }

    [Fact]
    public async Task VerifyAtLeastOne_ValidSignature_ShouldReturnTrue()
    {
        var (publicKey, privateKey) = GenerateRsaKeys();
        var data = "Verify me"u8.ToArray();
        using var source = new MemoryStream(data);
        using var signed = new MemoryStream();

        var signOp = new JSONSignature.SignOperation(JSONSignature.RSA_SHA256, publicKey, privateKey);
        await JSONSignature.SignAsync(source, signed, [signOp]);

        signed.Position = 0;
        var verifyOp = new JSONSignature.VerifyOperation(JSONSignature.RSA_SHA256, publicKey);
        var result = JSONSignature.VerifyAtLeastOne(signed, [verifyOp]);

        Assert.True(result);
    }

    [Fact]
    public void VerifyAtLeastOne_InvalidSignature_ShouldReturnFalse()
    {
        var (publicKey, privateKey) = GenerateRsaKeys();
        var data = "Invalid"u8.ToArray();
        using var signed = new MemoryStream(data);

        var verifyOp = new JSONSignature.VerifyOperation(JSONSignature.RSA_SHA256, publicKey);
        var result = JSONSignature.VerifyAtLeastOne(signed, [verifyOp]);

        Assert.False(result);
    }

    [Fact]
    public void Verify_NoVerifyOperations_ShouldThrowException()
    {
        var data = "Data"u8.ToArray();
        using var source = new MemoryStream(data);

        Assert.Throws<InvalidOperationException>(() => JSONSignature.Verify(source, []));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SignWithASingleKeyShouldWork(bool withHeaders)
    {
        var content = System.Text.Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(new { test = "test", extra = 234 }));
        var headers = withHeaders ? new System.Collections.Generic.Dictionary<string, string> { { "test", "1234" } } : null;
        var key = new RSACryptoServiceProvider(2048);

        using var source = new MemoryStream(content);
        using var target = new MemoryStream();

        await JSONSignature.SignAsync(source, target, [new JSONSignature.SignOperation(JSONSignature.RSA_SHA256, key.ToXmlString(false), key.ToXmlString(true), headers)]);

        target.Position = 0;

        var valids = JSONSignature.Verify(target, [new JSONSignature.VerifyOperation(JSONSignature.RSA_SHA256, key.ToXmlString(false))]);
        Assert.Single(valids);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SignWithMultipleAlgsShouldWork(bool withHeaders)
    {
        var content = System.Text.Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(new { test = "test", extra = 234 }));
        var headers = withHeaders ? new System.Collections.Generic.Dictionary<string, string> { { "test", "1234" } } : null;
        var key = new RSACryptoServiceProvider(2048);

        using var source = new MemoryStream(content);
        using var target = new MemoryStream();

        var algs = new[] { JSONSignature.RSA_SHA256, JSONSignature.RSA_SHA384, JSONSignature.RSA_SHA512 };

        await JSONSignature.SignAsync(source, target, algs.Select(x => new JSONSignature.SignOperation(x, key.ToXmlString(false), key.ToXmlString(true), headers)));

        target.Position = 0;
        var valids = JSONSignature.Verify(target, algs.Select(x => new JSONSignature.VerifyOperation(x, key.ToXmlString(false))));
        Assert.Equal(algs.Length, valids.Count());
        foreach (var alg in algs)
        {
            target.Position = 0;
            var valid = JSONSignature.Verify(target, [new JSONSignature.VerifyOperation(alg, key.ToXmlString(false))]);
            Assert.Single(valid);
            Assert.Equal(alg, valid.First().Algorithm);
            Assert.Equal(key.ToXmlString(false), valid.First().PublicKey);

            target.Position = 0;
            var hasOne = JSONSignature.VerifyAtLeastOne(target, [new JSONSignature.VerifyOperation(alg, key.ToXmlString(false))]);
            Assert.True(hasOne);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SignWithMultipleKeysShouldWork(bool withHeaders)
    {
        var content = System.Text.Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(new { test = "test", extra = 234 }));
        var headers = withHeaders ? new System.Collections.Generic.Dictionary<string, string> { { "test", "1234" } } : null;
        var keys = new[] { new RSACryptoServiceProvider(2048), new RSACryptoServiceProvider(2048), new RSACryptoServiceProvider(1024) };

        using var source = new MemoryStream(content);
        using var target = new MemoryStream();

        var algs = new[] { JSONSignature.RSA_SHA256, JSONSignature.RSA_SHA384, JSONSignature.RSA_SHA512 };
        var algkeycombos = algs.SelectMany(alg => keys.Select(key => (Alg: alg, Key: key))).ToArray();

        await JSONSignature.SignAsync(source, target, algkeycombos.Select(x => new JSONSignature.SignOperation(x.Alg, x.Key.ToXmlString(false), x.Key.ToXmlString(true), headers)));

        target.Position = 0;
        var valids = JSONSignature.Verify(target, algkeycombos.Select(x => new JSONSignature.VerifyOperation(x.Alg, x.Key.ToXmlString(false))));
        Assert.Equal(algkeycombos.Length, valids.Count());
        foreach (var alg in algkeycombos)
        {
            target.Position = 0;
            var valid = JSONSignature.Verify(target, [new JSONSignature.VerifyOperation(alg.Alg, alg.Key.ToXmlString(false))]);
            Assert.Single(valid);
            Assert.Equal(alg.Alg, valid.First().Algorithm);
            Assert.Equal(alg.Key.ToXmlString(false), valid.First().PublicKey);

            target.Position = 0;
            var hasOne = JSONSignature.VerifyAtLeastOne(target, [new JSONSignature.VerifyOperation(alg.Alg, alg.Key.ToXmlString(false))]);
            Assert.True(hasOne);
        }
    }

    [Fact]
    public void InvalidSignaturesShouldNotThrow()
    {
        var broken1 = new[] {
            // Invalid Base64 data
            "//SIGJSONv1: ####.abc=\n{\"x\": 1}"u8.ToArray(),

            // Invalid Base64 data
            "//SIGJSONv1: abc.abc\n{\"x\": 1}"u8.ToArray(),

            // Invalid header
            "//SIGJSONv1:abc=.abc=\n{\"x\": 1}"u8.ToArray(),

            // No newline
            "//SIGJSONv1: abc=.abc={\"x\": 1}"u8.ToArray(),

            // No newline
            "//SIGJSONv1: abc=.abc={\"x\": 1}\n"u8.ToArray(),

            // Extra newline
            "//SIGJSONv1: abc=.abc=\n{\"x\": 1}\n"u8.ToArray(),
        };

        var key = new RSACryptoServiceProvider(2048);
        foreach (var c in broken1)
        {
            using var source = new MemoryStream(c);
            using var target = new MemoryStream();

            var valids = JSONSignature.Verify(target, [new JSONSignature.VerifyOperation(JSONSignature.RSA_SHA256, key.ToXmlString(false))]);
            Assert.Empty(valids);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task TaintedDataShouldNotValidate(bool withHeaders)
    {
        var content = System.Text.Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(new { test = "test", extra = 234 }));
        var headers = withHeaders ? new System.Collections.Generic.Dictionary<string, string> { { "test", "1234" } } : null;
        var keys = new[] { new RSACryptoServiceProvider(2048), new RSACryptoServiceProvider(2048), new RSACryptoServiceProvider(1024) };

        using var source = new MemoryStream(content);
        using var target = new MemoryStream();

        var algs = new[] { JSONSignature.RSA_SHA256, JSONSignature.RSA_SHA384, JSONSignature.RSA_SHA512 };
        var algkeycombos = algs.SelectMany(alg => keys.Select(key => (Alg: alg, Key: key))).ToArray();

        await JSONSignature.SignAsync(source, target, algkeycombos.Select(x => new JSONSignature.SignOperation(x.Alg, x.Key.ToXmlString(false), x.Key.ToXmlString(true), headers)));

        // Taint the data
        target.Position = target.Length - 1;
        target.WriteByte((byte)'\n');

        target.Position = 0;
        var valids = JSONSignature.Verify(target, algkeycombos.Select(x => new JSONSignature.VerifyOperation(x.Alg, x.Key.ToXmlString(false))));
        Assert.Empty(valids);
    }

    [Theory]
    [InlineData(true, 1)] // Offset=1 breaks the JSON
    [InlineData(false, 1)]
    [InlineData(true, 4)] // Offset=4 changes the header key name
    [InlineData(false, 4)]
    public async Task TaintedHeadersShouldNotValidate(bool withHeaders, int offset)
    {
        var content = System.Text.Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(new { test = "test", extra = 234 }));
        var headers = withHeaders ? new System.Collections.Generic.Dictionary<string, string> { { "test", "1234" } } : null;
        var keys = new[] { new RSACryptoServiceProvider(2048), new RSACryptoServiceProvider(2048), new RSACryptoServiceProvider(1024) };

        using var source = new MemoryStream(content);
        using var target = new MemoryStream();

        var algs = new[] { JSONSignature.RSA_SHA256, JSONSignature.RSA_SHA384, JSONSignature.RSA_SHA512 };
        var algkeycombos = algs.SelectMany(alg => keys.Select(key => (Alg: alg, Key: key))).ToArray();

        await JSONSignature.SignAsync(source, target, algkeycombos.Select(x => new JSONSignature.SignOperation(x.Alg, x.Key.ToXmlString(false), x.Key.ToXmlString(true), headers)));

        // Taint the header data for the first signature
        target.Position = "//SIGJSONv1: ".Length + offset;
        var cur = target.ReadByte();
        target.Position -= 1;
        target.WriteByte((byte)(cur - 1));

        target.Position = 0;
        var valids = JSONSignature.Verify(target, algkeycombos.Select(x => new JSONSignature.VerifyOperation(x.Alg, x.Key.ToXmlString(false))));
        Assert.Equal(algkeycombos.Length - 1, valids.Count());
    }
}