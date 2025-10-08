# JsonSignature

JsonSignature is a C# library that implements the SIGJSON signature format for securing JSON files with hidden signatures. This allows you to embed cryptographic signatures directly into JSON data as comments, ensuring data integrity and authenticity without altering the JSON structure.

## Features

- **Hidden Signatures**: Signatures are embedded as comments at the beginning of the JSON file, making them invisible to standard JSON parsers.
- **Multiple Algorithms**: Supports RSA with SHA256, SHA384, and SHA512.
- **Multiple Keys**: Can sign with multiple keys and verify against multiple public keys.
- **Stream-Based**: Works with any seekable stream, allowing integration with various data sources.

## Installation

Add the JsonSignature package to your .NET project:

```bash
dotnet add package JsonSignature
```

Or manually reference the DLL in your project.

## Usage

### Signing Data

To sign a JSON stream:

```csharp
using JsonSignature;

// Generate or load your RSA keys
string publicKey = "..."; // Your RSA public key in XML format
string privateKey = "..."; // Your RSA private key in XML format

// Prepare the data to sign
using var source = new MemoryStream(Encoding.UTF8.GetBytes("{\"key\": \"value\"}"));
using var target = new MemoryStream();

// Create a sign operation
var signOp = new JSONSignature.SignOperation(JSONSignature.RSA_SHA256, publicKey, privateKey);

// Sign the data
await JSONSignature.SignAsync(source, target, [signOp]);

// The signed data is now in the target stream
```

### Verifying Data

To verify a signed JSON stream:

```csharp
// Reset the target stream to the beginning
target.Position = 0;

// Create a verify operation
var verifyOp = new JSONSignature.VerifyOperation(JSONSignature.RSA_SHA256, publicKey);

// Verify the signature
var matches = JSONSignature.Verify(target, [verifyOp]);

if (matches.Any())
{
    Console.WriteLine("Signature is valid!");
}
else
{
    Console.WriteLine("Signature is invalid.");
}
```

### Advanced Usage

#### Signing with Multiple Keys

```csharp
var signOps = new[]
{
    new JSONSignature.SignOperation(JSONSignature.RSA_SHA256, publicKey1, privateKey1),
    new JSONSignature.SignOperation(JSONSignature.RSA_SHA384, publicKey2, privateKey2)
};

await JSONSignature.SignAsync(source, target, signOps);
```

#### Verifying with Multiple Keys

```csharp
var verifyOps = new[]
{
    new JSONSignature.VerifyOperation(JSONSignature.RSA_SHA256, publicKey1),
    new JSONSignature.VerifyOperation(JSONSignature.RSA_SHA384, publicKey2)
};

var matches = JSONSignature.Verify(target, verifyOps);
```

#### Custom Signing/Verification Methods

You can provide custom signing and verification methods:

```csharp
var signOp = new JSONSignature.SignOperation(
    "CUSTOM",
    publicKey,
    privateKey,
    SignMethod: (stream, op) => /* your custom signing logic */
);

var verifyOp = new JSONSignature.VerifyOperation(
    "CUSTOM",
    publicKey,
    VerifyMethod: (stream, op, signature) => /* your custom verification logic */
);
```

## How It Works

SIGJSON embeds signatures as comment lines at the beginning of the JSON file. For example:

```
//SIGJSONv1: eyJhbGciOiJSUzI1NiIsImtleSI6InB1YmxpY0tleSIsInR5cCI6IlNJR0pTT052MSJ9.signature
{"key": "value"}
```

The signature includes:

- Algorithm used
- Public key
- Signature type
- Cryptographic signature of the header and content

This format ensures that the JSON remains valid while providing cryptographic integrity.

## Requirements

- .NET 8.0 or later
- RSA keys in XML format

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Related

This library is part of the Duplicati project ecosystem.
