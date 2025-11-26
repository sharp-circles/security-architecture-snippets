### 🛡️ Scenario 1: The Token Vendor (Machine-to-Machine Auth)

**Context:** Centralized auth for microservices. replacing hardcoded keys.

#### 📝 Cheat Sheet: M2M Auth

| Phase | Key Actions / Mental Triggers |
| :--- | :--- |
| **1. Ask** | 1. **Secret Zero:** "How do we trust the caller initially? (AWS IAM / K8s SA?)"<br>2. **Expiry:** "What is the Token TTL? (Short = Better)"<br>3. **Scope:** "Do we need specific permissions (Read/Write) or binary access?" |
| **2. Design** | • **Pattern:** OAuth2 Client Credentials Flow.<br>• **State:** Stateless Service + Policy DB (ACLs).<br>• **Security:** Sign tokens with **private key**. Verify caller via Platform Identity.<br>• **Logging:** Log *who* asked for *what*, never the token. |
| **3. Code** | • **Validation:** Check Inputs not null.<br>• **Logic:** `_repo.GetPolicy(source, target)` $\rightarrow$ If null, throw 403.<br>• **Crypto:** Use `JwtSecurityTokenHandler`. Set `Issuer` (Us) & `Audience` (Them). |

#### 💻 Code Implementation: `TokenService.cs`

```csharp
public class TokenService : ITokenService
{
    private readonly IPolicyRepository _repo;
    private readonly ILogger<TokenService> _logger;

    public TokenService(IPolicyRepository repo, ILogger<TokenService> logger)
    {
        _repo = repo;
        _logger = logger;
    }

    public async Task<string> GenerateToken(string sourceId, string targetId)
    {
        // 1. INPUT VALIDATION (Syntactic)
        if (string.IsNullOrWhiteSpace(sourceId) || string.IsNullOrWhiteSpace(targetId))
            throw new ValidationException("Source and Target IDs are required.", 400);

        // 2. AUTHORIZATION (Business Logic)
        // Check if a policy exists allowing Source -> Target
        var policy = await _repo.GetPolicyAsync(sourceId, targetId);

        if (policy == null)
        {
            _logger.LogWarning("Unauthorized token attempt. {Source} tried to access {Target}", sourceId, targetId);
            // Throwing SecurityException triggers 403 in your Global Handler
            throw new SecurityException("Access Denied: No policy found."); 
        }

        // 3. MINT TOKEN (Crypto Logic)
        var tokenHandler = new JwtSecurityTokenHandler();
        // In real app: Get key from KeyVault/HSM
        var key = Encoding.ASCII.GetBytes("My_Super_Secret_Key_For_Signing_Must_Be_32_Bytes!"); 

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] 
            { 
                new Claim("sub", sourceId), // Subject = Who is calling
                new Claim("scopes", policy.AllowedScopes) // RBAC
            }),
            Issuer = "TokenVendingMachine", // US
            Audience = targetId,            // THEM (The Target Service)
            Expires = DateTime.UtcNow.AddMinutes(15), // Short TTL
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        
        // 4. AUDIT LOG (Metadata Only)
        _logger.LogInformation("Token minted for {Source} -> {Target}. Expires: {Exp}", sourceId, targetId, tokenDescriptor.Expires);

        return tokenHandler.WriteToken(token);
    }
}
```

-----

### 🛡️ Scenario 2: Secure File Upload

**Context:** User profile pictures or PDF invoices. High risk of Malware/RCE.

#### 📝 Cheat Sheet: File Upload

| Phase | Key Actions / Mental Triggers |
| :--- | :--- |
| **1. Ask** | 1. **Processing:** "Do we parse it immediately? (Risk of parser exploit)"<br>2. **Storage:** "Public bucket or Private?"<br>3. **Restrictions:** "Max size? Allowed types?" |
| **2. Design** | • **Pattern:** **Quarantine Pattern** (Upload $\rightarrow$ Scan $\rightarrow$ Move).<br>• **Defense:** Magic Bytes check (Header) vs Extension.<br>• **Sanitization:** Rename file to `GUID.ext` (Prevent path traversal).<br>• **Async:** Offload scanning to a worker/queue. |
| **3. Code** | • **Stream:** Read stream start for Magic Bytes, then reset position.<br>• **Logic:** `if (header != allowed) throw 400`.<br>• **Storage:** Send to Repo with the *new* safe name. |

#### 💻 Code Implementation: `FileUploadService.cs`

```csharp
public class FileUploadService : IFileUploadService
{
    private readonly IStorageRepository _storage;
    private readonly ILogger<FileUploadService> _logger;

    // Magic Bytes: The First few bytes of a file that identify format
    private static readonly Dictionary<string, byte[]> _allowedSignatures = new()
    {
        { ".jpg", new byte[] { 0xFF, 0xD8, 0xFF } },
        { ".png", new byte[] { 0x89, 0x50, 0x4E, 0x47 } },
        { ".pdf", new byte[] { 0x25, 0x50, 0x44, 0x46 } }
    };

    public FileUploadService(IStorageRepository storage, ILogger<FileUploadService> logger)
    {
        _storage = storage;
        _logger = logger;
    }

    public async Task UploadFile(string originalName, Stream fileStream)
    {
        // 1. VALIDATION (Size)
        if (fileStream.Length > 5 * 1024 * 1024) // 5MB Limit
            throw new ValidationException("File exceeds 5MB limit.", 400);

        // 2. VALIDATION (Extension)
        var ext = Path.GetExtension(originalName).ToLower();
        if (!_allowedSignatures.ContainsKey(ext))
            throw new ValidationException("File type not supported.", 400);

        // 3. VALIDATION (Magic Bytes - Deep Check)
        using (var reader = new BinaryReader(fileStream, Encoding.Default, leaveOpen: true))
        {
            var headerBytes = reader.ReadBytes(_allowedSignatures[ext].Length);
            
            // Critical: Reset stream position so we can save it later!
            fileStream.Position = 0;

            if (!headerBytes.SequenceEqual(_allowedSignatures[ext]))
            {
                _logger.LogWarning("File spoofing attempt. Ext: {Ext} but Header mismatch.", ext);
                throw new SecurityException("Invalid file format.");
            }
        }

        // 4. SANITIZATION (Renaming)
        // Prevent Path Traversal and Overwrites
        var safeFileName = $"{Guid.NewGuid()}{ext}";

        // 5. STORE (Quarantine)
        await _storage.SaveToQuarantine(safeFileName, fileStream);
        
        _logger.LogInformation("File uploaded to quarantine: {Name}", safeFileName);
    }
}
```

-----

### 🛡️ Scenario 3: Secrets Vault (Storage)

**Context:** Storing sensitive API keys or passwords.

#### 📝 Cheat Sheet: Secrets Vault

| Phase | Key Actions / Mental Triggers |
| :--- | :--- |
| **1. Ask** | 1. **Access:** "Is this read-heavy? (Caching strategy)"<br>2. **Isolation:** "Multi-tenant? (Need TenantId in query)"<br>3. **Encryption:** "Do we need encryption at rest? (Yes)" |
| **2. Design** | • **Pattern:** **Envelope Encryption** (Master Key encrypts Data Key, Data Key encrypts Data).<br>• **Algorithm:** AES-GCM (Provides Integrity + Confidentiality).<br>• **Key Mgmt:** Master Key lives in HSM/Cloud Vault, never in DB. |
| **3. Code** | • **AuthZ:** `if (!user.IsAdmin) throw 403`.<br>• **Logic:** Generate nonce (IV). Encrypt. Return `Ciphertext` + `Nonce` + `Tag`.<br>• **Repo:** Save all 3 parts to DB. |

#### 💻 Code Implementation: `SecretService.cs`

```csharp
public class SecretService : ISecretService
{
    private readonly ISecretRepository _repo;
    private readonly ILogger<SecretService> _logger;

    public SecretService(ISecretRepository repo, ILogger<SecretService> logger)
    {
        _repo = repo;
        _logger = logger;
    }

    public async Task StoreSecret(UserContext user, string keyName, string plainTextValue)
    {
        // 1. AUTHORIZATION (RBAC)
        if (user.Role != "Admin")
            throw new SecurityException("Only Admins can write secrets.");

        // 2. VALIDATION (Size)
        if (plainTextValue.Length > 4096)
            throw new ValidationException("Secret payload too large.", 400);

        // 3. ENCRYPTION (AES-GCM)
        // Mocking the key derivation from a Master Key
        byte[] key = new byte[32]; 
        byte[] nonce = new byte[12]; // GCM standard IV size
        byte[] tag = new byte[16];   // Auth Tag
        byte[] cipherText = new byte[Encoding.UTF8.GetByteCount(plainTextValue)];

        // Fill nonce with random noise
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(nonce);
        }

        // Encrypt
        using (var aes = new AesGcm(key))
        {
            var plainBytes = Encoding.UTF8.GetBytes(plainTextValue);
            aes.Encrypt(nonce, plainBytes, cipherText, tag);
        }

        // 4. STORAGE
        // We must store the Nonce and Tag to decrypt later!
        var entity = new SecretEntity
        {
            TenantId = user.TenantId,
            KeyName = keyName,
            CipherBase64 = Convert.ToBase64String(cipherText),
            NonceBase64 = Convert.ToBase64String(nonce),
            TagBase64 = Convert.ToBase64String(tag)
        };

        await _repo.SaveSecretAsync(entity);
        
        _logger.LogInformation("Secret {Name} stored for Tenant {Tenant}", keyName, user.TenantId);
    }
}
```

-----

### 🛡️ Scenario 4: Rate Limiter (Availability)

**Context:** Stopping Brute Force or DoS attacks.

#### 📝 Cheat Sheet: Rate Limiter

| Phase | Key Actions / Mental Triggers |
| :--- | :--- |
| **1. Ask** | 1. **Granularity:** "Per IP (weak) or UserID (strong)?"<br>2. **Scope:** "Distributed (Cluster)? (Need Redis)"<br>3. **Response:** "Block (429) or CAPTCHA?" |
| **2. Design** | • **Pattern:** **Token Bucket** or **Fixed Window**.<br>• **Storage:** **Redis** (Must use atomic operations / Lua).<br>• **Fail Mode:** "Fail Open" (If Redis dies, allow traffic) vs "Fail Closed". |
| **3. Code** | • **Key:** `ratelimit:{userId}`.<br>• **Logic:** `count = cache.Increment()`.<br>• **Expiry:** `if (count == 1) cache.SetExpire()`.<br>• **Check:** `if (count > limit) throw 429`. |

#### 💻 Code Implementation: `RateLimitService.cs`

```csharp
public class RateLimitService : IRateLimitService
{
    private readonly ICacheRepository _cache; // Wraps Redis
    private readonly ILogger<RateLimitService> _logger;

    private const int MAX_REQUESTS = 5;
    private const int WINDOW_SECONDS = 60;

    public RateLimitService(ICacheRepository cache, ILogger<RateLimitService> logger)
    {
        _cache = cache;
        _logger = logger;
    }

    public async Task CheckRateLimit(string userId)
    {
        // 1. KEY DEFINITION
        string cacheKey = $"ratelimit:{userId}";

        try 
        {
            // 2. ATOMIC INCREMENT
            // Returns the new value. If key didn't exist, creates it at 0 then increments to 1.
            long currentCount = await _cache.IncrementAsync(cacheKey);

            // 3. SET EXPIRY (On first request only)
            if (currentCount == 1)
            {
                await _cache.SetExpiryAsync(cacheKey, TimeSpan.FromSeconds(WINDOW_SECONDS));
            }

            // 4. ENFORCEMENT
            if (currentCount > MAX_REQUESTS)
            {
                _logger.LogWarning("Rate limit exceeded for User {User}", userId);
                
                // Throw ValidationException with specific code (handled by Global Handler)
                throw new ValidationException("Too many requests. Try again later.", 429);
            }
        }
        catch (ValidationException) 
        {
            throw; // Bubble up the 429
        }
        catch (Exception ex)
        {
            // 5. FAIL OPEN STRATEGY
            // If Redis is down, we Log the error but ALLOW the user to proceed.
            // Availability > Strict Enforcement (usually)
            _logger.LogError(ex, "Rate limit cache failed. Failing open.");
        }
    }
}
```


---

### 1. Token Vendor (M2M Auth)
*Context: Centralized auth for microservices.*

**1. Requirements**
* **Trust:** Platform Identity (AWS IAM / K8s SA) $\to$ No hardcoded secrets.
* **TTL:** Short (e.g., 15 mins).
* **Policy:** RBAC (Scopes) or ACL (Binary access).

**2. Design**
* **Pattern:** OAuth2 Client Credentials Flow.
* **State:** Stateless Service + Policy DB.
* **Crypto:** Sign with **Private Key** (Us), Verify with **Public Key** (Them).

**3. Code**
* **Validation:** Check IDs not null.
* **Logic:** `_repo.GetPolicy(source, target)` $\rightarrow$ If null, throw 403.
* **Mint:** `JwtSecurityTokenHandler` $\rightarrow$ Issuer=Us, Audience=Them, Claims=Scopes.

---

### 2. Secure File Upload
*Context: Profile pics/Invoices. Malware risk.*

**1. Requirements**
* **Processing:** Async (don't parse immediately).
* **Storage:** Quarantine Bucket first.
* **Restrictions:** Strict Allowlist (Type & Size).

**2. Design**
* **Pattern:** Quarantine Pattern (Upload $\rightarrow$ Scan $\rightarrow$ Move).
* **Defense:** Check **Magic Bytes** (Hex Header), ignore Extension.
* **Sanitization:** Rename file to `GUID.ext` (Prevent traversal).

**3. Code**
* **Stream:** Read first N bytes $\rightarrow$ Reset Position.
* **Logic:** `if (!header.SequenceEqual(allowed)) throw 400`.
* **Store:** Save to Quarantine repo with new name.

---

### 3. Secrets Vault (Storage)
*Context: Storing API Keys/Passwords.*

**1. Requirements**
* **Access:** Read-heavy (Cache strategy needed).
* **Isolation:** Multi-tenant (TenantId in every query).
* **Security:** Encryption at Rest (Mandatory).

**2. Design**
* **Pattern:** Envelope Encryption (Master Key encrypts Data Key).
* **Algo:** **AES-GCM** (Confidentiality + Integrity).
* **Key Mgmt:** Master Key in HSM/Vault, never DB.

**3. Code**
* **AuthZ:** `if (!user.IsAdmin) throw 403`.
* **Crypto:** Generate Nonce. Encrypt. Return `Cipher` + `Nonce` + `Tag`.
* **Store:** Save all 3 parts to DB.

---

### 4. Rate Limiter (Availability)
*Context: Anti-Brute Force / DoS.*

**1. Requirements**
* **Granularity:** UserID (Strong) > IP (Weak/NAT issues).
* **Scope:** Distributed (Redis Cluster).
* **Fail Mode:** Fail Open (Availability > Security).

**2. Design**
* **Pattern:** Token Bucket / Fixed Window.
* **Storage:** Redis (Atomic `INCR` operations).
* **Headers:** Return `X-RateLimit-Remaining`.

**3. Code**
* **Key:** `limit:{userId}`.
* **Logic:** `count = Redis.Increment()`.
* **Expiry:** `if (count == 1) Redis.SetExpire()`.
* **Check:** `if (count > limit) throw 429`.

---

### 5. Secure User Login
*Context: Customer Portal Password Auth.*

**1. Requirements**
* **Storage:** Hashing (Not Encryption).
* **Speed:** Slow (Argon2/Bcrypt) to stop brute force.
* **Session:** Opaque Token (Revocable) > JWT.

**2. Design**
* **Algo:** **Argon2id**.
* **Salt:** Unique random salt per user.
* **Compare:** **Constant-Time** (Stop timing attacks).

**3. Code**
* **Hash:** `Argon2.Hash(inputPassword, userSalt)`.
* **Verify:** `CryptographicOperations.FixedTimeEquals(hash, dbHash)`.
* **Session:** Generate Random String $\to$ Store in Redis (`Key=String`, `Value=UserId`).

---

### 💻 Code Implementation: `AuthService.cs`

```csharp
using System.Security.Cryptography; // For RandomNumberGenerator & FixedTimeEquals

public class AuthService : IAuthService
{
    private readonly IUserRepository _userRepo;
    private readonly ICacheRepository _sessionCache; // Redis wrapper for Opaque Tokens
    private readonly ILogger<AuthService> _logger;

    public AuthService(IUserRepository userRepo, ICacheRepository sessionCache, ILogger<AuthService> logger)
    {
        _userRepo = userRepo;
        _sessionCache = sessionCache;
        _logger = logger;
    }

    public async Task<string> Login(string email, string inputPassword)
    {
        // 1. RETRIEVAL (Get User + Salt + Stored Hash)
        var user = await _userRepo.GetByEmailAsync(email);
        
        // SECURITY: Handle "User Not Found" carefully. 
        // In prod, you might want to fake a hash calculation here to prevent "User Enumeration" 
        // (timing difference between "User not found" vs "Wrong password").
        if (user == null) 
            throw new SecurityException("Invalid credentials.");

        // 2. HASHING (Argon2id or PBKDF2)
        // We use the SALT stored with the user to hash the Input Password
        byte[] inputHash = HashPassword(inputPassword, user.Salt);

        // 3. COMPARISON (Constant-Time)
        // CRITICAL: Do NOT use "==". It stops at the first wrong character (fast fail),
        // allowing timing attacks. FixedTimeEquals checks every byte.
        bool isMatch = CryptographicOperations.FixedTimeEquals(inputHash, user.StoredHash);

        if (!isMatch)
        {
            _logger.LogWarning("Failed login attempt for {Email}", email);
            throw new SecurityException("Invalid credentials.");
        }

        // 4. SESSION (Opaque Token)
        // Generate a random string (Reference Token)
        string opaqueToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        // Store in Redis: Key=Token, Value=UserId. Expiry=30m.
        await _sessionCache.SetAsync(opaqueToken, user.Id, TimeSpan.FromMinutes(30));

        return opaqueToken;
    }

    // Helper: Logic usually provided by libraries like 'Konscious.Security.Cryptography.Argon2'
    private byte[] HashPassword(string password, byte[] salt)
    {
        // Mocking the Argon2id call for the interview snippet
        using var hasher = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
        return hasher.GetBytes(32);
    }
}
```

-----

### 🛡️ Secure Design Patterns (Architecture)

| # | Pattern | Concept | Simulation Example & Implementation |
| :--- | :--- | :--- | :--- |
| **1** | **Zero Trust** | "Never trust, always verify." Assume the network is hostile. | **Token Vendor:** We don't rely on IP allowlists. We verify the K8s/AWS Platform Token for *every* single request (`[Authorize]`). |
| **2** | **Defense in Depth** | Multiple redundant layers of security controls. | **File Upload:** We check the File Extension (Layer 1) **AND** the Magic Bytes (Layer 2) **AND** use a Quarantine Bucket (Layer 3). |
| **3** | **Least Privilege** | Granting only the minimum permissions necessary. | **Token Vendor:** The Policy DB (`AllowedScopes`) ensures Service A gets "Read-Only" access, not "Admin," when talking to Service B. |
| **4** | **Fail Secure** | If the system crashes, it must default to a secure state (not reveal info). | **Global Exception Handler:** If the DB throws an error, we catch it and return a generic `500 Internal Error` JSON, preventing Stack Trace leakage. |
| **5** | **Complete Mediation** | Every access request must be checked against authority. | **Secrets Vault:** We don't check permissions once at login; we check `user.Role == "Admin"` inside the `StoreSecret` method for *every* write operation. |

---

### 🕸️ OWASP Top 10 (Vulnerabilities)

| # | OWASP Category | Concept | Simulation Example & Implementation |
| :--- | :--- | :--- | :--- |
| **6** | **A01: Broken Access Control** | Users acting outside their permissions (IDOR). | **Secrets Vault:** Adding `TenantId` to every Repository query. Prevents User A from reading User B's secrets by changing an ID. |
| **7** | **A02: Cryptographic Failures** | Weak encryption or hashing (e.g., MD5, ECB). | **User Login / Vault:** Using **Argon2id** (Memory hard) for passwords and **AES-GCM** (Authenticated Encryption) for secrets. |
| **8** | **A03: Injection** | Untrusted data sent to an interpreter (SQLi, Path Traversal). | **File Upload:** Renaming the file to `GUID.ext`. Prevents "Path Traversal" attacks where a filename like `../../etc/passwd` overwrites system files. |
| **9** | **A07: Identification & Auth Failures** | Weak passwords, no rate limiting, credential stuffing. | **Rate Limiter:** Implementing the Redis Token Bucket. Stops attackers from Brute Forcing the login endpoint or M2M tokens. |
| **10** | **A09: Logging & Monitoring Failures** | Not logging enough, or logging too much (Secrets). | **Token Vendor:** The fix we made to the Logger. Logging "Token Minted for ID: X" (Audit Trail) but **never** logging the JWT string itself. |
