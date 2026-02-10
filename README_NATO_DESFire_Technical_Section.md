## Technical notes: DESFire NDEF layout (language-agnostic)

This project implements a **“pure” NFC Forum Type 4 / DESFire** layout for a NATO-style NDEF card:

- **One DESFire application**
  - **AID:** `000001` (note: DESFire AIDs are *LSB-first* when sent in native commands)
  - **ISO DF name:** `D2760000850101` (NFC Forum NDEF Tag Application)
- **Three standard data files inside the app**
  - **File 1 (CC):** ISO FID `E103`, fileNo `0x01`, size **23 bytes**
  - **File 2 (NPS):** ISO FID `E104`, fileNo `0x02`, size **NPS capacity**, final policy **readable / not writable**
  - **File 3 (EXTRA):** ISO FID `E105`, fileNo `0x03`, size **computed from free memory**, **read/write**

The layout works with readers that expect **Type 4 NDEF files**:
- Each NDEF file is stored as: **`NLEN(2 bytes big-endian) + NDEF message bytes`**
- We intentionally write **only** `NLEN + message` (**no zero padding**).

---

### Transport and command style

- **Transport:** ISO-DEP (ISO 14443-4) to DESFire.
- **Native DESFire APDU wrapper used here:**
  - `CLA = 0x90`
  - `INS = <DESFire native instruction>`
  - `P1=0x00 P2=0x00`
  - `Lc = len(data)` then `<data>` then `Le=0x00`
- The GitHub code relies on a DESFire library for authentication / read / write primitives, but the *on-card layout* is independent of language/library.

Native `INS` values used:
- `0xCA` — CreateApplication
- `0xCD` — CreateStdDataFile
- `0x5F` — ChangeFileSettings (used to lock E104)
- PICC free memory is read via `FreeMemory` (library call). The returned value is **3 bytes LSB-first**.

**Status byte convention in this implementation:** we check the **last response byte**; `0x00` indicates success (some operations treat `0xDE` as “already exists / duplicate”).

---

### Step-by-step layout creation that worked

1) **Destructive PICC format**
- Select PICC/master AID `000000`
- Authenticate with default key (here: DES, 8 bytes of `0x00`)
- Format PICC (erases apps/files)

2) **Create NFC Forum NDEF application (AID 000001)**
- **CreateApplication (INS `0xCA`) data body used:**

  - AID (LSB-first): `01 00 00`
  - Key settings: `0F`
  - App settings (ISO support): `21`
  - Keys: `05 01` (5 keys, DES)
  - ISO DF name: `D2 76 00 00 85 01 01`

  **Full body (hex):**
  `01 00 00 0F 21 05 01 D2 76 00 00 85 01 01`

3) **Select the NDEF app and authenticate**
- Select AID `000001`
- Authenticate to key number `0x00` with the default DES key

4) **Create CC file (fileNo=0x01, FID E103, size 23)**
- **CreateStdDataFile (INS `0xCD`) body format:**

  `fileNo(1) | ISO FID(2, LE in our body) | comm(1) | accessRights(2) | fileSize(3, LSB)`

  For CC:
  - fileNo: `01`
  - ISO FID: `E103` → bytes `03 E1` in this body
  - comm: `00` (plain)
  - access rights: `EE EE` (free access for read/write/change)
  - size: `17 00 00` (23 decimal)

  **Body (hex):**
  `01 03 E1 00 EE EE 17 00 00`

5) **Create NPS file (fileNo=0x02, FID E104, size = NPS capacity)**
- During formatting we create E104 with *temporary permissive access* so we can seed it and later write the final payload.
- comm: `00` (plain)
- access rights during creation: `EE EE` (free)
- size: `npsSize` encoded as 3 bytes LSB

  **Example body (hex, placeholders for size):**
  `02 04 E1 00 EE EE <sz0> <sz1> <sz2>`

6) **Compute and create EXTRA file (fileNo=0x03, FID E105)**
- We compute EXTRA size from the card’s **remaining free memory**:
  - Read free memory at the **PICC level** (select `000000` before calling FreeMemory)
  - Interpret as **LSB-first 3-byte integer**
  - Apply a safety margin and align to DESFire allocation granularity:

    - `safety = 128 bytes`
    - `min = 256 bytes`
    - `extraSize = floor_to_32( max(remaining - safety, 256) )`

- Then re-select the NDEF app and authenticate again.
- Create E105 with:
  - comm: `00` (plain)
  - access: `EE EE` (free R/W)
  - size: `extraSize` as 3 bytes LSB

  **Example body (hex, placeholders for size):**
  `03 05 E1 00 EE EE <sz0> <sz1> <sz2>`

7) **Write CC contents (23 bytes) with TWO File Control TLVs**

CC file header (bytes `0..6`):
- `CCLEN` = `0x17` (23 bytes)
- Mapping version = `0x20` (2.0)
- MLe = `0x003B`
- MLc = `0x0034`

**CC bytes (hex), with placeholders for file sizes:**

- Header (7 bytes):
  `00 17 20 00 3B 00 34`

- TLV #1 (NPS E104):
  - T = `04` (NDEF File Control TLV)
  - L = `06`
  - File ID = `E104` → `E1 04`
  - Max NDEF size = `npsCapacityBytes` in **2 bytes big-endian** (Hi, Lo)
  - Read access = `00`
  - Write access = `FF` (not allowed)

  `04 06 E1 04 <npsHi> <npsLo> 00 FF`

- TLV #2 (EXTRA E105):
  - File ID = `E105` → `E1 05`
  - Max NDEF size = `extraSize` in **2 bytes big-endian**
  - Read access = `00`
  - Write access = `00` (free)

  `04 06 E1 05 <exHi> <exLo> 00 00`

Putting it together (23 bytes total):
```
00 17 20 00 3B 00 34
04 06 E1 04 <npsHi> <npsLo> 00 FF
04 06 E1 05 <exHi>  <exLo>  00 00
```

**Important:** the CC file is exactly **23 bytes** in this implementation (not 32).

8) **Seed the NPS file with an initial NDEF record (no padding)**
- Build your NDEF message (here: a single MIME record).
- Write sequence used (reliable on DESFire):
  1. Write `NLEN = 0x0000` (2 bytes) at offset 0
  2. Write `NLEN + NDEF message` starting at offset 0

**NDEF file format:**
- `NLEN` is **big-endian** length of the NDEF message in bytes.
- The “message” is the raw NDEF bytes (one or more records).

Example of the written bytes:
- `NLEN_hi NLEN_lo <NDEF...>`

---

### Access rights that worked (E104 “readable / blocked for writes”)

DESFire file access rights are a pair of bytes that encode four nibbles:

- Byte0 = `(RW << 4) | Change`
- Byte1 = `(Read << 4) | Write`

Where each nibble is a key number, or a special value:
- `0xE` = free access
- `0xF` = never / blocked

**Final policy for E104 (NPS):**
- Read: `E` (free)
- Write: `F` (blocked)
- Read/Write: `F` (blocked)
- Change: `F` (blocked)

This corresponds to:
- Byte0 = `FF`  (RW=F, Change=F)
- Byte1 = `EF`  (Read=E, Write=F)

In this project we apply that final policy using **ChangeFileSettings (INS `0x5F`)** after writing the real NPS payload:

- comm settings: `00` (plain)
- access rights: `FF EF`

**Body (hex):**
`02 00 FF EF`

**Why lock *after* writing?**
- If you lock E104 during formatting, later issuer writes will fail with authentication/permission errors.
- The working flow is:
  1. Create E104 with permissive rights (`EE EE`) so it can be written
  2. Write the final NPS content
  3. Lock E104 to `FF EF`

---

### MIME record structure used (for reference)

The code writes a **single NDEF MIME record** (TNF = `0x02`, “media-type”).
It supports both:
- **Short Record (SR=1)** when payload < 256 bytes
- **Normal record (SR=0)** otherwise

### MIME record structure and payload semantics (for reference)

For the NATO card payloads we standardise on **gzip-compressed JSON payloads** with
versioned, namespaced MIME types. These are not generic placeholders: they correspond
to two specific, agreed data semantics.

#### MIME types used

- **NPS (E104, read-only)**  
  `application/x.nps.gzip.v1-0`

- **EXTRA (E105, read/write)**  
  `application/x.ext.gzip.v1-0`

#### Payload meaning

Each MIME type implies both **compression** and **content semantics**:

- **E104 / NPS (read-only)**
    - Payload is a **gzip-compressed binary JSON document**
    - The uncompressed content represents the **Historic NPS dataset**
    - Structure conforms to the agreed **Draft‑07 JSON Schema** for Historic NPS
    - This file is written by the issuer and locked after writing

- **E105 / EXTRA (read/write)**
    - Payload is a **gzip-compressed binary JSON document**
    - The uncompressed content represents the **Operational (mutable) NPS dataset**
    - Structure conforms to the agreed **Draft‑07 JSON Schema** for Operational NPS
    - This file is intended to be updated in the field

Both schemas are publicly viewable here:  
https://ipsmern-dep.azurewebsites.net/schemaviewer

#### Why gzip + versioned MIME types

This combination was chosen because:

- The `.gzip` suffix makes compression **explicit**, so readers know decompression
  is mandatory before parsing.
- The `v1-0` suffix provides **forwards compatibility**, allowing schema evolution
  without breaking existing readers.
- The MIME strings remain standard ASCII and fit cleanly into an
  **NFC Forum NDEF MIME record** (TNF = `0x02`).

#### NDEF record structure

A single-record MIME NDEF message is used in all cases:

- Record header: `MB=1`, `ME=1`, `SR` as required, `TNF=0x02`
- TYPE LENGTH: length of the ASCII MIME string
- PAYLOAD LENGTH:
    - 1 byte if `SR=1` (payload < 256 bytes)
    - 4 bytes if `SR=0`
- TYPE: MIME string (e.g. `application/x.nps.gzip.v1-0`)
- PAYLOAD: `gzip( JSON bytes )`

**Important:** regardless of record size or SR flag, the enclosing **Type 4 NDEF file**
always follows the same wrapper:

```
[ NLEN (2 bytes, big‑endian) ][ NDEF message bytes ]
```

Readers must always:
1. Read `NLEN`
2. Read exactly `NLEN` bytes of NDEF data
3. Parse the MIME record
4. Decompress the payload


---

### Practical interoperability tips

- Always write `NLEN=0` before writing a new message to avoid partial reads during an update window.
- Prefer writing exactly `2 + NLEN` bytes (no padding) rather than rewriting the entire file with zeros.
- Keep CC consistent with your real file sizes:
  - TLV Max NDEF size is **2 bytes big-endian**
  - DESFire file sizes are stored as **3 bytes LSB** in native create-file bodies
- When using FreeMemory to size E105:
  - select PICC/master first (AID `000000`)
  - subtract a small safety margin and align to 32 bytes
  - re-select NDEF app before creating files or writing
