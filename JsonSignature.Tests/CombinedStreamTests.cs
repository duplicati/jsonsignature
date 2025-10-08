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

using System.Text;

namespace JsonSignature.Tests;

public class CombinedStreamTests
{
    [Fact]
    public void CombinedStream_ReadsSequentially()
    {
        var data1 = "Hello"u8.ToArray();
        var data2 = " World"u8.ToArray();
        using var stream1 = new MemoryStream(data1);
        using var stream2 = new MemoryStream(data2);
        using var combined = new CombinedStream([stream1, stream2], leaveOpen: true);

        var buffer = new byte[11];
        var totalRead = 0;
        var bytesRead = combined.Read(buffer, totalRead, 11 - totalRead);
        totalRead += bytesRead;
        bytesRead = combined.Read(buffer, totalRead, 11 - totalRead);
        totalRead += bytesRead;

        Assert.Equal(11, totalRead);
        Assert.Equal("Hello World", Encoding.UTF8.GetString(buffer));
    }

    [Fact]
    public void CombinedStream_ReadPartial()
    {
        var data1 = "Hi"u8.ToArray();
        var data2 = "There"u8.ToArray();
        using var stream1 = new MemoryStream(data1);
        using var stream2 = new MemoryStream(data2);
        using var combined = new CombinedStream([stream1, stream2], leaveOpen: true);

        var buffer = new byte[3];
        var bytesRead1 = combined.Read(buffer, 0, 3);
        Assert.Equal(2, bytesRead1);
        Assert.Equal("Hi", Encoding.UTF8.GetString(buffer[..bytesRead1]));

        var bytesRead2 = combined.Read(buffer, 0, 3);
        Assert.Equal(3, bytesRead2);
        Assert.Equal("The", Encoding.UTF8.GetString(buffer[..bytesRead2]));
    }

    [Fact]
    public void CombinedStream_CanRead_True()
    {
        using var stream = new MemoryStream();
        using var combined = new CombinedStream([stream], leaveOpen: true);
        Assert.True(combined.CanRead);
    }

    [Fact]
    public void CombinedStream_CanWrite_False()
    {
        using var stream = new MemoryStream();
        using var combined = new CombinedStream([stream], leaveOpen: true);
        Assert.False(combined.CanWrite);
    }

    [Fact]
    public void CombinedStream_CanSeek_False()
    {
        using var stream = new MemoryStream();
        using var combined = new CombinedStream([stream], leaveOpen: true);
        Assert.False(combined.CanSeek);
    }

    [Fact]
    public void CombinedStream_LeaveOpenTrue_DoesNotDisposeStreams()
    {
        var stream = new MemoryStream();
        using var combined = new CombinedStream([stream], leaveOpen: true);
        combined.Dispose();
        // Should not throw, stream still usable
        stream.WriteByte(1);
    }

    [Fact]
    public void CombinedStream_LeaveOpenFalse_DisposesStreams()
    {
        var stream = new MemoryStream();
        using var combined = new CombinedStream([stream], leaveOpen: false);
        combined.Dispose();
        // Should throw ObjectDisposedException
        Assert.Throws<ObjectDisposedException>(() => stream.WriteByte(1));
    }

    [Fact]
    public void CombinedStream_EmptyStreams_ReadsZero()
    {
        using var combined = new CombinedStream([], leaveOpen: true);
        var buffer = new byte[1];
        var bytesRead = combined.Read(buffer, 0, 1);
        Assert.Equal(0, bytesRead);
    }

    [Fact]
    public void CombinedStream_Length_ThrowsNotSupported()
    {
        using var stream = new MemoryStream();
        using var combined = new CombinedStream([stream], leaveOpen: true);
        Assert.Throws<NotSupportedException>(() => _ = combined.Length);
    }

    [Fact]
    public void CombinedStream_Position_ThrowsNotSupported()
    {
        using var stream = new MemoryStream();
        using var combined = new CombinedStream([stream], leaveOpen: true);
        Assert.Throws<NotSupportedException>(() => _ = combined.Position);
        Assert.Throws<NotSupportedException>(() => combined.Position = 0);
    }

    [Fact]
    public void CombinedStream_Seek_ThrowsNotSupported()
    {
        using var stream = new MemoryStream();
        using var combined = new CombinedStream([stream], leaveOpen: true);
        Assert.Throws<NotSupportedException>(() => combined.Seek(0, SeekOrigin.Begin));
    }

    [Fact]
    public void CombinedStream_SetLength_ThrowsNotSupported()
    {
        using var stream = new MemoryStream();
        using var combined = new CombinedStream([stream], leaveOpen: true);
        Assert.Throws<NotSupportedException>(() => combined.SetLength(0));
    }

    [Fact]
    public void CombinedStream_Write_ThrowsNotSupported()
    {
        using var stream = new MemoryStream();
        using var combined = new CombinedStream([stream], leaveOpen: true);
        Assert.Throws<NotSupportedException>(() => combined.Write([], 0, 0));
    }
}