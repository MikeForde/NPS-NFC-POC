# NATO Patient Summary NFC Android App

<p align="center">
  <img src="NPS_POC_App.png" alt="NPS POC Android App" width="400"/>
  <br/>
  <em>Patient data shown is fictitious</em>
</p>

This Android application is a demonstration and reference implementation for writing and reading NATO Patient Summary (NPS) data to MIFARE DESFire EV1/EV2/EV3 NFC cards using several interoperable approaches.

It accompanies the IPS MERN WebApp and demonstrates how NATO-aligned patient summaries can be stored on NFC media in a way that balances:
- Universal readability (standard NDEF)
- Controlled mutability (read-only vs read/write)
- DESFire-grade security and structure
- Offline usability

## Key Features
### 🔹 Dual NFC Reader Support
The app is reader-agnostic and supports two methods of interacting with NFC cards:
1.  **Internal NFC**: Use the Android device's built-in NFC antenna.
2.  **External USB Reader**: Support for the **ACS ACR122U** USB NFC reader. When connected via USB-OTG, the app automatically detects the reader and uses it as a high-performance alternative for card operations.

### 🔹 Three NFC Storage Modes
The app supports three distinct NFC layouts, selectable from the UI:

#### 1️⃣ Pure DESFire (App 665544)
- Stores two binary blobs in a private DESFire application
- Fully DESFire-native (not visible to standard NDEF readers)
- Read/write access controlled via DESFire keys

#### 2️⃣ Dual Mode (Type-4 NDEF + DESFire)
- Read-only NATO Patient Summary stored as standard Type-4 NDEF
- Visible to any NFC reader (Android, iOS, desktop)
- Read/write “extra” data stored in a private DESFire app

#### 3️⃣ NDEF Mode (Two NDEF files in App 000001)
- Fully aligned with the proposed NATO NPS DESFire layout
- A single NDEF application (000001) containing NPS (RO) and Extra data (RW)
- Vanilla NDEF readers see only the NPS; advanced apps can access both

## WebApp Integration
The app integrates with the IPS MERN WebApp to fetch patient data.
- **Backends**: Local (localhost:5049) or Azure Cloud.
- **Protection Levels**: None, Encrypted (JWE), or Omitted identifiers.

## Hardware & Card Requirements
- **Cards**: MIFARE DESFire EV1 / EV2 / EV3 (8KB or 16KB recommended).
- **Internal NFC**: Android device with NFC and IsoDep support.
- **External NFC**: ACS ACR122U USB reader + USB-OTG adapter.

## Technical Highlights
### Reader-Agnostic Architecture
The app uses a unified `ApduTransport` interface. This abstraction allows the core DESFire and NDEF logic to operate identically across different hardware:
- `AndroidIsoDepTransport`: Wraps the native Android `IsoDep` class.
- `Acr122uApduTransport`: Communicates with the external reader via the ACS Smart Card library.

### DESFire & NDEF Details
- Manual construction of NDEF records (supporting short and long formats).
- Correct handling of NLEN, MIME media types, and CC file TLVs.
- Explicit creation of Applications and Standard data files (E103, E104, E105).
- Read-only enforcement via DESFire access rights.

## Project Structure (Key Classes)

| Class | Purpose |
|-------|---------|
| `MainActivity` | UI coordination and unified transport routing |
| `ApduTransport` | Interface for cross-reader hardware abstraction |
| `Acr122uUsbController` | Manages USB permissions and reader lifecycle |
| `DesfireHelper` | Pure DESFire read/write implementation |
| `NDEFHelper` | Dual mode (Type-4 NDEF + DESFire) |
| `NATOHelper` | NATO-compliant two-NDEF-file implementation |

## Development & Testing Notes
### External Reader Usage
1. Connect the ACR122U to the Android device.
2. Grant USB permission when prompted.
3. Select an action (e.g., "Read DES") and tap the card on the USB reader.

### Dependencies
- `acssmc`: ACS Smart Card Library for Android
- `nfcjlib`: DESFire communication library
- `okhttp`, `gson`, `androidx`

# License & Usage
This code is provided for demonstration, research, and interoperability testing purposes. Security parameters, keys, and formats must be reviewed before any operational use.
