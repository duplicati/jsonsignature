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
}