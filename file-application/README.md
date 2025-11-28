# File Application SDK

A Go SDK for interacting with IPFS gateway services, providing secure file upload and download capabilities with built-in encryption/decryption support using Proxy Re-Encryption (PRE) and DID-based access control.

## Features

- **File Upload & Download**: Upload and download files to/from IPFS gateway
- **DID Encryption**: Files encrypted with owner's public key (resolved from DID)
- **Proxy Re-Encryption (PRE)**: Share file access without decrypting the original file
- **Public & Private Access**: Support for both public (unencrypted) and private (encrypted) file access
- **Verifiable Credentials (VC)**: Access control using Owner VC and Accessible VC
- **Flexible Key Resolution**: Built-in DID resolver or implement custom public key retrieval
- **Streaming Support**: Efficient streaming encryption/decryption for large files
- **S3-like Interface**: Familiar PutObject/GetObject API similar to AWS S3

## System Requirements

- **Go 1.24.6** or higher
- **Gateway Service**: Intermediate service that handles file upload/download
- **DID Resolver**: Service to resolve DIDs (Decentralized Identifiers) to retrieve public keys
- **Private Keys**: Each role (issuer, owner, application, viewer) needs their own private key

## Installation

Add the SDK to your Go project:

```bash
go get github.com/pilacorp/nda-sfs-sdk/file-application
```

## Important Concepts

Before getting started, you need to understand some key concepts:

### DID (Decentralized Identifier)

DID is a decentralized identifier representing an entity (user, application). Example: `did:example:owner`.

### Roles in the System

| Role | Description |
|------|-------------|
| **Application** | Your application, acts as intermediary between user and Gateway |
| **Issuer** | Entity that issues credentials, confirms file ownership |
| **Owner** | File owner, has rights to upload and share files |
| **Viewer** | Person granted access by owner to view files |

### Verifiable Credential (VC)

VC is a digital certificate proving a certain right. This SDK uses 2 types:

- **Owner VC**: Proves owner owns the file (created during upload)
- **Accessible VC**: Proves viewer is allowed to access file (created by owner to share)

### CID (Content Identifier)

CID is the unique identifier of a file on IPFS, returned after successful upload.

### DID Encryption

The SDK uses **DID Encryption** to encrypt files. This means:

- Files are encrypted with the owner's public key when uploaded
- Owner can share access with others without decrypting the original file
- Viewer receives a "re-encryption key" (as Accessible VC) to decrypt the file

## Client Initialization

The client is the main object for interacting with the Gateway. You need to provide configuration information when initializing.

### Required Parameters

| Parameter | Description |
|-----------|-------------|
| `Endpoint` | Gateway service URL. SDK automatically adds `/api/v1` to path if not present |
| `DIDResolverURL` | DID Resolver URL to resolve public keys from DID documents |
| `ApplicationDID` | DID representing your application |
| `GatewayTrustJWT` | JWT token proving the application is trusted by Gateway |
| `AccessibleSchemaURL` | Schema URL defining the structure of Owner VC and Accessible VC |
| `AppPrivKeyHex` | Application private key (hex format), used to sign VP tokens along with ApplicationDID and related DID information |

### Optional Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `Timeout` | HTTP request timeout | 30 seconds |
| `DefaultHeaders` | Default headers added to all requests | None |
| `HTTPClient` | Custom HTTP client | Created with configured timeout |
| `CryptProvider` | Custom crypto provider for encryption/decryption | DID-Encryption (PRE) |
| `AuthClient` | Custom auth client | ECDSA provider |
| `IssuerPrivKeyHex` | Issuer private key, used to create Owner VC during upload | None |
| `OwnerPrivKeyHex` | Owner private key, used to decrypt files or create Accessible VC | None |
| `ViewerPrivKeyHex` | Viewer private key, used to decrypt files when downloading | None |

### Initialization Example

```go
import (
    "time"
    "log"
    
    "github.com/aws/aws-sdk-go-v2/aws"
    filesdk "github.com/pilacorp/nda-sfs-sdk/file-application"
)

// Initialize client with full configuration
client, err := filesdk.New(filesdk.Config{
    // === REQUIRED PARAMETERS ===
    
    // Gateway service URL
    // SDK will automatically add /api/v1 if you only provide domain
    Endpoint: aws.String("https://gateway.example.com"),
    
    // DID Resolver URL
    // Used to resolve DID to public key
    DIDResolverURL: aws.String("https://resolver.example.com/api/v1/did"),
    
    // Application DID
    // Represents your application in the system
    ApplicationDID: aws.String("did:example:app"),
    
    // JWT token to authenticate with Gateway
    // Gateway will verify this token before processing requests
    GatewayTrustJWT: aws.String("<your-gateway-trust-jwt>"),
    
    // Schema URL for Owner VC and Accessible VC
    // Defines the data structure of credentials
    AccessibleSchemaURL: aws.String("https://schema.example.com/api/v1/schemas/<schema-id>"),
    
    // Application private key (hex format)
    // Used to sign VP (Verifiable Presentation) tokens
    AppPrivKeyHex: aws.String("<app-private-key-hex>"),
    
    // === OPTIONAL PARAMETERS ===
    
    // HTTP request timeout
    // Should increase if uploading/downloading large files
    Timeout: 30 * time.Second,
    
    // Issuer private key (hex format)
    // Required when you want to upload files and create Owner VC
    IssuerPrivKeyHex: aws.String("<issuer-private-key-hex>"),
    
    // Owner private key (hex format)
    // Required when owner downloads files or creates Accessible VC
    OwnerPrivKeyHex: aws.String("<owner-private-key-hex>"),
    
    // Viewer private key (hex format)
    // Required when viewer downloads shared files
    ViewerPrivKeyHex: aws.String("<viewer-private-key-hex>"),
})

// Always check for errors during initialization
if err != nil {
    log.Fatalf("Failed to initialize client: %v", err)
}
```

## Upload File

Uploading a file is the first step in the workflow. Upon successful upload, you will receive:

- **CID**: Unique identifier of the file on IPFS
- **Owner VC JWT**: Credential proving file ownership issued by the issuer

Both pieces of information are very important and should be saved for later use.

### Access Types

| Access Type | Description | When to Use |
|-------------|-------------|-------------|
| `AccessTypePublic` | File is not encrypted | Public files, anyone can view |
| `AccessTypePrivate` | File is encrypted with DID-Encryption | Private files, only owner and authorized users can view |

### Upload Example

```go
import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "log"
    "os"
    
    "github.com/aws/aws-sdk-go-v2/aws"
    filesdk "github.com/pilacorp/nda-sfs-sdk/file-application"
)

// Create context for request
// Context helps control timeout and cancellation
ctx := context.Background()

// Step 1: Read file content to upload
// You can read from actual file or create content in memory
fileContent, err := os.ReadFile("path/to/your/file.txt")
if err != nil {
    log.Fatalf("Failed to read file: %v", err)
}

// Step 2: Call PutObject to upload file
uploadOutput, err := client.PutObject(ctx, &filesdk.PutObjectInput{
    // Bucket: Owner DID (file owner)
    // File will be stored under this owner's "directory"
    Bucket: aws.String("did:example:owner"),
    
    // Key: File name
    // This is the display name, not the CID
    Key: aws.String("document.txt"),
    
    // Body: File content as io.Reader
    // Use bytes.NewReader to convert []byte to Reader
    Body: bytes.NewReader(fileContent),
    
    // AccessType: Access type
    // - AccessTypePublic: Not encrypted
    // - AccessTypePrivate: Encrypted with DID-Encryption
    AccessType: filesdk.AccessTypePrivate,
    
    // IssuerDID: Issuer DID
    // Issuer will sign Owner VC to confirm ownership
    IssuerDID: aws.String("did:example:issuer"),
    
    // ContentType: MIME type of the file
    ContentType: aws.String("text/plain"),
    
    // Metadata: Additional information
    // Authorization is the owner's JWT token
    Metadata: map[string]string{
        "Authorization": "<your-owner-jwt-token>",
    },
})

// Step 3: Check for errors
if err != nil {
    log.Fatalf("Upload failed: %v", err)
}

// Step 4: Parse upload result
// Important information is in SSEKMSEncryptionContext
type UploadInfo struct {
    CID         string `json:"cid"`         // File identifier on IPFS
    OwnerDID    string `json:"ownerDID"`    // Owner DID
    FileName    string `json:"fileName"`    // File name
    FileType    string `json:"fileType"`    // MIME type
    AccessLevel string `json:"accessLevel"` // public or private
    IssuerDID   string `json:"issuerDID"`   // Issuer DID
    OwnerVCJWT  string `json:"ownerVCJWT"`  // Owner VC JWT - VERY IMPORTANT
    CreatedAt   string `json:"createdAt"`   // Creation time
}

var uploadInfo UploadInfo
err = json.Unmarshal([]byte(*uploadOutput.SSEKMSEncryptionContext), &uploadInfo)
if err != nil {
    log.Fatalf("Failed to parse upload info: %v", err)
}

// Step 5: Save CID and OwnerVCJWT
// These are the two most important pieces of information, save to database
fmt.Printf("Upload successful!\n")
fmt.Printf("CID: %s\n", uploadInfo.CID)
fmt.Printf("Owner VC JWT: %s\n", uploadInfo.OwnerVCJWT)

// IMPORTANT: Save CID and OwnerVCJWT to database
// You will need them to:
// 1. Download file later
// 2. Grant access to others
```

## Grant Access (Create Accessible VC)

When you want to share a file with someone else (viewer), you need to create an **Accessible VC**. This is a credential that allows the viewer to decrypt and view your file.

### Access Granting Process

1. Owner has uploaded file (has CID and Owner VC JWT)
2. Owner calls `PostAccessibleVC` with viewer's DID
3. SDK creates re-encryption key and packages it into Accessible VC
4. Owner sends Accessible VC to viewer
5. Viewer embeds Accessible VC into their VP JWT to download

### Create Accessible VC Example

```go
import (
    "context"
    "fmt"
    "log"
    
    "github.com/aws/aws-sdk-go-v2/aws"
    filesdk "github.com/pilacorp/nda-sfs-sdk/file-application"
)

// Create context
ctx := context.Background()

// Required information (from upload step)
ownerDID := "did:example:owner"           // Owner DID
viewerDID := "did:example:viewer"         // DID of person granted access
cid := "<cid-from-upload>"                // CID from upload step
ownerVCJWT := "<owner-vc-jwt-from-upload>" // Owner VC JWT from upload step

// Call PostAccessibleVC to create Accessible VC
accessibleVC, err := client.PostAccessibleVC(ctx, &filesdk.PostAccessibleVCInput{
    // OwnerDID: Owner DID (file owner)
    OwnerDID: aws.String(ownerDID),
    
    // ViewerDID: Viewer DID (person granted access to view)
    // SDK will create re-encryption key for this viewer
    ViewerDID: aws.String(viewerDID),
    
    // CID: File identifier
    // From upload result
    CID: aws.String(cid),
    
    // VCOwner: Owner VC JWT
    // Proves you are the owner of the file
    VCOwner: aws.String(ownerVCJWT),
}, filesdk.WithOwnerPrivKeyHex(ownerPrivKeyHex))

// Check for errors
if err != nil {
    log.Fatalf("Failed to create Accessible VC: %v", err)
}

// Get Accessible VC JWT
accessibleVCJWT := *accessibleVC.VCJWT
fmt.Printf("Accessible VC created successfully!\n")
fmt.Printf("Accessible VC JWT: %s\n", accessibleVCJWT)

// SEND accessibleVCJWT to viewer
// Viewer will embed this JWT into their VP to download file
```

## Download File

There are 2 download scenarios:

1. **Owner downloads their own file**: Uses Owner VC JWT
2. **Viewer downloads shared file**: Uses Accessible VC JWT

### Owner Download File

Owner can download their own file anytime by providing Owner VC JWT.

```go
import (
    "context"
    "fmt"
    "io"
    "log"
    
    "github.com/aws/aws-sdk-go-v2/aws"
    filesdk "github.com/pilacorp/nda-sfs-sdk/file-application"
)

// Create context
ctx := context.Background()

// File information to download
ownerDID := "did:example:owner"  // Owner DID
cid := "<cid>"                   // File CID
ownerVPJWT := "<owner-vp-jwt>"   // VP JWT containing Owner VC

// Call GetObject to download file
result, err := client.GetObject(ctx, &filesdk.GetObjectInput{
    // Bucket: Owner DID
    Bucket: aws.String(ownerDID),
    
    // Key: File CID (not file name)
    Key: aws.String(cid),
    
    // Metadata: Contains Authorization header
    // VP JWT must contain Owner VC to prove ownership
    Metadata: map[string]string{
        "Authorization": ownerVPJWT,
    },
})

// Check for errors
if err != nil {
    log.Fatalf("Download failed: %v", err)
}

// IMPORTANT: Always close Body after reading
// Use defer to ensure Body is closed
defer result.Body.Close()

// Read file content
// result.Body is io.ReadCloser, can be read like normal file
data, err := io.ReadAll(result.Body)
if err != nil {
    log.Fatalf("Failed to read file: %v", err)
}

// Use file content
fmt.Printf("File content: %s\n", string(data))

// Read file metadata
fmt.Printf("\nMetadata:\n")
fmt.Printf("  CID: %s\n", result.Metadata["cid"])
fmt.Printf("  Content-Type: %s\n", result.Metadata["content-type"])
fmt.Printf("  Size: %s bytes\n", result.Metadata["size"])
```

### Viewer Download Shared File

Viewer needs to have Accessible VC from owner. Viewer also needs to provide their private key to decrypt the file.

```go
import (
    "context"
    "fmt"
    "io"
    "log"
    "time"
    
    "github.com/aws/aws-sdk-go-v2/aws"
    filesdk "github.com/pilacorp/nda-sfs-sdk/file-application"
)

// Step 1: Initialize client with ViewerPrivKeyHex
// Viewer needs to provide their private key to decrypt file
viewerClient, err := filesdk.New(filesdk.Config{
    // Required parameters (same as above)
    Endpoint:            aws.String("https://gateway.example.com"),
    DIDResolverURL:      aws.String("https://resolver.example.com/api/v1/did"),
    ApplicationDID:      aws.String("did:example:app"),
    GatewayTrustJWT:     aws.String("<gateway-trust-jwt>"),
    AccessibleSchemaURL: aws.String("https://schema.example.com/api/v1/schemas/<schema-id>"),
    AppPrivKeyHex:       aws.String("<app-private-key-hex>"),
    
    // IMPORTANT: Viewer private key
    // SDK uses this key to decrypt file
    ViewerPrivKeyHex: aws.String("<viewer-private-key-hex>"),
})
if err != nil {
    log.Fatalf("Failed to initialize client: %v", err)
}

// Step 2: Create context
ctx := context.Background()

// Step 3: File information to download
ownerDID := "did:example:owner"
cid := "<cid>"

// viewerVPJWT: Viewer's VP JWT
// This VP must contain Accessible VC that owner granted
viewerVPJWT := "<viewer-vp-jwt-with-accessible-vc>"

// Step 4: Call GetObject
result, err := viewerClient.GetObject(ctx, &filesdk.GetObjectInput{
    // Bucket: Owner DID (not viewer)
    // Because file belongs to owner
    Bucket: aws.String(ownerDID),
    
    // Key: File CID
    Key: aws.String(cid),
    
    // Authorization: VP JWT containing Accessible VC
    Metadata: map[string]string{
        "Authorization": viewerVPJWT,
    },
}, filesdk.WithDecryptPrivKeyHex(viewerPrivKeyHex))

// Check for errors
if err != nil {
    log.Fatalf("Download failed: %v", err)
}
defer result.Body.Close()

// Read file content
data, err := io.ReadAll(result.Body)
if err != nil {
    log.Fatalf("Failed to read file: %v", err)
}

fmt.Printf("Download successful!\n")
fmt.Printf("Content: %s\n", string(data))
```

## Error Handling

| Error Code | Cause | Solution |
|------------|-------|----------|
| **401 Unauthorized** | JWT expired or invalid | Create new JWT with longer expiration |
| **403 Forbidden** | No permission to access file | Check Accessible VC or contact owner to grant access |
| **404 Not Found** | CID does not exist | Check CID again, file may have been deleted |
| **Connection refused** | Gateway not running | Check endpoint and Gateway service status |
| **Timeout** | Request took too long | Increase Timeout value in config, or use custom HTTPClient without timeout |

## Best Practices

### 1. Secure Private Keys

**NEVER** hardcode private keys in source code. Instead:

```go
// Use environment variables
appPrivKey := os.Getenv("APP_PRIVATE_KEY")

// Or use secret manager (AWS Secrets Manager, HashiCorp Vault, ...)
```

### 2. Always Close Body After Reading

```go
result, err := client.GetObject(ctx, input)
if err != nil {
    return err
}
// Use defer immediately after error check
defer result.Body.Close()
```

### 3. Store CID and VC

After upload, save `CID` and `OwnerVCJWT` to database:

```go
// Example saving to database
db.Save(&FileRecord{
    CID:        uploadInfo.CID,
    OwnerVCJWT: uploadInfo.OwnerVCJWT,
    OwnerDID:   ownerDID,
    FileName:   fileName,
    CreatedAt:  time.Now(),
})
```

### 4. Handle Timeout Appropriately

```go
// Small files (< 10MB): 30 seconds is enough
Timeout: 30 * time.Second

// Large files (> 100MB): Increase timeout
Timeout: 5 * time.Minute

// Very large files: Consider using custom HTTPClient with separate timeout
```

### 5. Retry on Temporary Errors

```go
// Simple retry example
maxRetries := 3
for i := 0; i < maxRetries; i++ {
    result, err := client.GetObject(ctx, input)
    if err == nil {
        // Success
        break
    }
    
    // Wait before retry
    time.Sleep(time.Duration(i+1) * time.Second)
}
```

## Complete Example

Below is a complete example of the upload → grant access → download workflow:

```go
package main

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "time"

    "github.com/aws/aws-sdk-go-v2/aws"
    filesdk "github.com/pilacorp/nda-sfs-sdk/file-application"
)

func main() {
    // ========================================
    // STEP 1: INITIALIZE CLIENT
    // ========================================
    
    ctx := context.Background()
    
    // Create client with full configuration
    client, err := filesdk.New(filesdk.Config{
        // Required parameters
        Endpoint:            aws.String("https://gateway.example.com"),
        DIDResolverURL:      aws.String("https://resolver.example.com/api/v1/did"),
        ApplicationDID:      aws.String("did:example:app"),
        GatewayTrustJWT:     aws.String("<your-gateway-trust-jwt>"),
        AccessibleSchemaURL: aws.String("https://schema.example.com/api/v1/schemas/<schema-id>"),
        AppPrivKeyHex:       aws.String("<app-private-key-hex>"),
        
        // Optional parameters
        Timeout:          30 * time.Second,
        IssuerPrivKeyHex: aws.String("<issuer-private-key-hex>"),
        OwnerPrivKeyHex:  aws.String("<owner-private-key-hex>"),
    })
    if err != nil {
        log.Fatalf("Failed to initialize client: %v", err)
    }
    
    fmt.Println("✓ Client initialized successfully")

    // ========================================
    // STEP 2: UPLOAD FILE
    // ========================================
    
    // File content to upload
    content := []byte("This is secret file content!")
    
    // Call PutObject to upload
    uploadOutput, err := client.PutObject(ctx, &filesdk.PutObjectInput{
        Bucket:     aws.String("did:example:owner"),
        Key:        aws.String("secret.txt"),
        Body:       bytes.NewReader(content),
        AccessType: filesdk.AccessTypePrivate,
        IssuerDID:  aws.String("did:example:issuer"),
        ContentType: aws.String("text/plain"),
        Metadata: map[string]string{
            "Authorization": "<owner-jwt>",
        },
    })
    if err != nil {
        log.Fatalf("Upload failed: %v", err)
    }
    
    // Parse upload result
    var uploadInfo struct {
        CID        string `json:"cid"`
        OwnerVCJWT string `json:"ownerVCJWT"`
    }
    json.Unmarshal([]byte(*uploadOutput.SSEKMSEncryptionContext), &uploadInfo)
    
    fmt.Println("✓ Upload successful")
    fmt.Printf("  CID: %s\n", uploadInfo.CID)

    // ========================================
    // STEP 3: GRANT ACCESS TO VIEWER
    // ========================================
    
    // Create Accessible VC for viewer
    accessibleVC, err := client.PostAccessibleVC(ctx, &filesdk.PostAccessibleVCInput{
        OwnerDID:  aws.String("did:example:owner"),
        ViewerDID: aws.String("did:example:viewer"),
        CID:       aws.String(uploadInfo.CID),
        VCOwner:   aws.String(uploadInfo.OwnerVCJWT),
    })
    if err != nil {
        log.Fatalf("Failed to create Accessible VC: %v", err)
    }
    
    fmt.Println("✓ Access granted to viewer")
    fmt.Printf("  Accessible VC: %s...\n", (*accessibleVC.VCJWT)[:50])

    // ========================================
    // STEP 4: OWNER DOWNLOAD FILE
    // ========================================
    
    // Owner downloads their own file
    result, err := client.GetObject(ctx, &filesdk.GetObjectInput{
        Bucket: aws.String("did:example:owner"),
        Key:    aws.String(uploadInfo.CID),
        Metadata: map[string]string{
            "Authorization": "<owner-jwt>",
        },
    })
    if err != nil {
        log.Fatalf("Download failed: %v", err)
    }
    defer result.Body.Close()
    
    // Read file content
    data, _ := io.ReadAll(result.Body)
    
    fmt.Println("✓ Download successful")
    fmt.Printf("  Content: %s\n", string(data))
    
    // ========================================
    // COMPLETE
    // ========================================
    
    fmt.Println("\n=== WORKFLOW COMPLETE ===")
}
```

## Quick Start (examples/main.go)

The repository ships with a runnable example that lives in `examples/main.go`. It demonstrates the full workflow (upload → create accessible VC → download) and is the fastest way to verify your environment.

1. Update the constants at the top of `examples/main.go` with the DIDs, private keys, schema IDs, and JWTs that match your deployment.
2. Run the upload flow (default when no argument is provided):

   ```bash
   go run examples/main.go
   # or
   go run examples/main.go upload
   ```

   This calls `PutObject`, prints the CID, and dumps the owner VC info returned inside `SSEKMSEncryptionContext`.

3. Copy the printed CID and owner VC JWT into the `const` block inside `runCreateAccessibleVC`, then issue an accessible VC for a viewer:

   ```bash
   go run examples/main.go create-vc
   ```

   Under the hood this invokes `PostAccessibleVC`, which resolves the viewer DID, creates a re-capsule, and signs the credential with the owner private key.

4. Finally, place the accessible VC (as a VP JWT) inside the `runDownload` constants and download/decrypt the file:

   ```bash
   go run examples/main.go download
   ```

If you prefer to embed the SDK directly, the example code shows how to instantiate `filesdk.New`, call `PutObject`, `GetObject`, and `PostAccessibleVC`, and how to pass Authorization metadata. Copy the relevant snippets into your service once you have confirmed the end-to-end flow.

## API Reference

### Client

#### `New(cfg Config) (*Client, error)`

Creates a new File Application SDK client.

**Config:**
- `Endpoint` (*string, required): Gateway endpoint URL (e.g., "http://localhost:8083")
- `Timeout` (time.Duration): HTTP client timeout (default: 30s)
- `DefaultHeaders` (http.Header): Default headers for all requests
- `HTTPClient` (*http.Client): Custom HTTP client (optional)
- `CryptProvider` (crypt.Provider): Custom decryptor provider for private downloads (defaults to built-in PRE provider)
- `AuthClient` (auth.Auth): Custom auth client (optional, defaults to ECDSA provider)
- `DIDResolverURL` (*string, required): DID resolver base URL
- `ApplicationDID` (*string, required): Application DID for creating VP tokens
- `GatewayTrustJWT` (*string, required): Gateway trust JWT for VP token creation
- `AccessibleSchemaURL` (*string, required): Schema URL for owner file credentials
- `AppPrivKeyHex` (*string): Application private key hex for signing VP tokens
- `IssuerPrivKeyHex` (*string): Issuer private key hex for creating owner VC during upload
- `OwnerPrivKeyHex` (*string): Owner private key hex used as default for:
  - Decrypting files when owner downloads their own files (GetObject)
  - Re-encapsulating capsules when owner creates accessible VCs (PostAccessibleVC)

### PutObject

#### `PutObject(ctx context.Context, input *PutObjectInput, opts ...PutObjectOpt) (*PutObjectOutput, error)`

Uploads a file to the gateway.

**PutObjectInput:**
- `Bucket` (*string, required): Owner DID (bucket identifier)
- `Key` (*string, required): Name of the file
- `Body` (io.Reader, required): File content reader
- `Metadata` (map[string]string): Additional metadata (e.g., "Authorization" header)
- `AccessType` (AccessType): `AccessTypePublic` or `AccessTypePrivate` (default: AccessTypePublic)
- `ContentType` (*string): MIME type of the file (default: "application/octet-stream")
- `IssuerDID` (*string, required): Issuer DID stored alongside the object

**PutObjectOpt Options:**
- `WithEncryptorChunkSize(chunkSize int)`: Set chunk size for PRE encryption (default: 1MB)
- `WithIssuerPrivKeyHex(privKeyHex string)`: Override issuer private key for creating owner VC
- `WithUploadApplicationPrivKeyHex(privKeyHex string)`: Set application private key for VP token signing

**Returns:**
- `*PutObjectOutput`: Contains `SSEKMSEncryptionContext` (JSON string with CID, Capsule, OwnerVCJWT, etc.)

### GetObject

#### `GetObject(ctx context.Context, input *GetObjectInput, opts ...GetObjectOpt) (*GetObjectOutput, error)`

Downloads a file from the gateway.

**GetObjectInput:**
- `Bucket` (*string, required): Owner DID that was used during upload
- `Key` (*string, required): CID of the file
- `Metadata` (map[string]string): Additional metadata (e.g., "Authorization" header with JWT token)

**GetObjectOpt Options:**
- `WithDecryptPrivKeyHex(privKeyHex string)`: Private key for decrypting private files
  - If not provided, uses `OwnerPrivKeyHex` from config (for owner downloads)
  - Required for viewer downloads (use viewer's private key)
- `WithDownloadApplicationPrivKeyHex(privKeyHex string)`: Application private key for VP token signing

**Returns:**
- `*GetObjectOutput`: Contains:
  - `Body` (io.ReadCloser): Decrypted file content stream (must be closed by caller)
  - `Metadata` (map[string]string): Object metadata (CID, size, content-type, etc.)

### PostAccessibleVC

#### `PostAccessibleVC(ctx context.Context, input *PostAccessibleVCInput, opts ...PostAccessibleVCOpt) (*PostAccessibleVCOutput, error)`

Creates an Accessible VC to grant viewer access to a private file.

**PostAccessibleVCInput:**
- `OwnerDID` (*string, required): Owner DID
- `ViewerDID` (*string, required): Viewer DID to grant access
- `CID` (*string, required): File CID
- `VCOwner` (*string, required): Owner VC JWT

**PostAccessibleVCOpt Options:**
- `WithOwnerPrivKeyHex(privKeyHex string)`: Owner private key for re-encapsulation

**Returns:**
- `*PostAccessibleVCOutput`: Contains `VCJWT` (Accessible VC JWT)

## Encryption

The SDK uses Proxy Re-Encryption (PRE) for private file encryption. Files encrypted with the owner's public key can be re-encrypted for viewers using accessible VCs.

### Encryption Flow

1. **Upload (Private File)**:
   - File is encrypted with owner's public key (resolved from DID)
   - Capsule is generated and stored with the file
   - Owner VC is created using issuer's private key

2. **Download (Owner)**:
   - Owner uses their private key to decrypt
   - Private key can be set via `WithDecryptPrivKeyHex` or `OwnerPrivKeyHex` config

3. **Download (Viewer)**:
   - Viewer must have an accessible VC (created via `PostAccessibleVC`)
   - Viewer uses their private key via `WithDecryptPrivKeyHex`
   - Gateway re-encrypts using the accessible VC

### Custom Decryption Providers

You can provide a custom `crypt.Provider` when constructing the client to customize decryption behavior:

```go
type CustomProvider struct {
    // Your custom provider implementation
}

func (p *CustomProvider) NewPreDecryptor(ctx context.Context, capsule string, opts ...crypt.ProviderOpt) (*pre.Decryptor, error) {
    // Custom decryption logic
    // Pull keys from secure stores, implement custom re-encryption, etc.
}

client, err := filesdk.New(filesdk.Config{
    Endpoint:      aws.String(gatewayURL),
    CryptProvider: &CustomProvider{},
})
```

## Access Control & Credentials

The SDK uses Verifiable Credentials (VCs) and Verifiable Presentations (VPs) for access control.

### Owner VC

When a file is uploaded, an Owner VC is automatically created that proves:
- The issuer granted the owner access to the file
- The file CID and capsule information

### Accessible VC

To grant a viewer access to a private file, create an Accessible VC using `PostAccessibleVC`. The viewer can then use this VC in a VP token to download the file.

### Public Key Resolution

Public keys are automatically resolved from DIDs using the configured `DIDResolverURL`. The SDK resolves the verification method `<ownerDID>#key-1` to get the public key for encryption.

## Architecture

### Package Structure

```
file-sdk/
├── api.go              # Client initialization and configuration
├── api-put-object.go   # File upload implementation
├── api-get-object.go   # File download implementation
├── api-post-accessible-vc.go # Accessible VC creation
├── pkg/
│   ├── crypt/          # Encryption/decryption
│   │   ├── provider.go # Encryptor/Decryptor interfaces
│   │   └── pre_provider.go # PRE implementation
│   ├── resolver/       # DID resolver
│   │   └── resolver.go
│   └── credential/     # JWT credential handling
│       ├── jwt.go
│       └── vc.go
└── examples/           # Example code
```

### Key Components

1. **Client**: Main SDK client for file operations
2. **Encryptor/Decryptor Interfaces**: Abstract interfaces allowing any encryption algorithm implementation
3. **PRE Provider**: Built-in Proxy Re-Encryption implementation (can be replaced with custom algorithms)
4. **Resolver Interface**: Abstract interface for public key retrieval (default DID resolver included)
5. **DID Resolver**: Default implementation that resolves public keys from DID documents

## Requirements

- Go 1.24.6 or higher
- Access to an IPFS gateway endpoint
- DID resolver endpoint for resolving public keys
- Application DID and gateway trust JWT for VP token creation
