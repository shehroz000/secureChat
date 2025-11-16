# Wireshark Setup Guide for Secure Chat

## Step 1: Install Wireshark

### macOS
```bash
# Using Homebrew (recommended)
brew install --cask wireshark

# Or download from: https://www.wireshark.org/download.html
```

### Linux
```bash
sudo apt-get update
sudo apt-get install wireshark
```

### Windows
Download from: https://www.wireshark.org/download.html

## Step 2: Configure Wireshark for Localhost Capture

### macOS - Enable Loopback Interface
1. Open Wireshark
2. Go to **Capture** → **Options**
3. Look for interface `lo0` (Loopback)
4. If `lo0` is not available, you may need to install additional tools:
   ```bash
   brew install --cask wireshark-chmodbpf
   ```
5. Or use `any` interface to capture all traffic

### Alternative: Use tcpdump and import
```bash
# Capture on loopback interface
sudo tcpdump -i lo0 -w capture.pcap port 8888

# Then open capture.pcap in Wireshark
```

## Step 3: Capture Traffic

### Method 1: Direct Capture in Wireshark
1. **Start Wireshark**
2. **Select interface**: Choose `lo0` (loopback) or `any`
3. **Set display filter**: `tcp.port == 8888`
4. **Click Start** (blue shark fin icon)
5. **Run your server and client** (in separate terminals)
6. **Perform a chat session**
7. **Stop capture** when done

### Method 2: Command Line Capture
```bash
# Start capture before running server/client
sudo tcpdump -i lo0 -w securechat_capture.pcap port 8888

# In another terminal, run your server and client
# When done, stop tcpdump (Ctrl+C)
# Open securechat_capture.pcap in Wireshark
```

## Step 4: Analyze the Capture

### Display Filters to Use

**Show only your application traffic:**
```
tcp.port == 8888
```

**Show only data packets (exclude SYN/ACK):**
```
tcp.port == 8888 && tcp.len > 0
```

**Show encrypted payloads:**
```
tcp.port == 8888 && tcp.data
```

**Follow TCP stream (see full conversation):**
- Right-click on a packet → **Follow** → **TCP Stream**
- This shows the full conversation between client and server

### What to Look For

#### ✅ Good Signs (Encrypted Traffic)
- **No plaintext passwords**: Credentials should be encrypted
- **No plaintext messages**: Chat messages should be base64-encoded ciphertext
- **JSON structure visible**: You should see JSON with encrypted fields like:
  ```json
  {"type":"register","encrypted":"base64_encoded_data..."}
  {"type":"msg","ct":"base64_ciphertext...","sig":"base64_signature..."}
  ```
- **Certificate exchange**: You should see PEM-encoded certificates in hello messages

#### ❌ Bad Signs (Security Issues)
- Plaintext passwords visible
- Unencrypted chat messages
- Sensitive data in clear text

## Step 5: Create Evidence Screenshots

### Required Screenshots for Assignment

1. **Encrypted Payload View**
   - Filter: `tcp.port == 8888 && tcp.data`
   - Show a packet with encrypted data
   - Highlight that no plaintext is visible

2. **Certificate Exchange**
   - Show hello/server_hello messages
   - Highlight certificate data (PEM format)

3. **Encrypted Message**
   - Show a chat message packet
   - Highlight the `ct` (ciphertext) field
   - Show that plaintext is not visible

4. **Full Session Overview**
   - Statistics → Protocol Hierarchy
   - Show TCP traffic breakdown

## Step 6: Export Evidence

### Save Filtered Capture
1. Apply your filter: `tcp.port == 8888`
2. File → Export Specified Packets
3. Choose "Displayed" packets only
4. Save as `securechat_encrypted_only.pcap`

### Export Packet Details
1. Select important packets
2. File → Export Packet Dissections → As Plain Text
3. Save analysis notes

## Example Workflow

```bash
# Terminal 1: Start Wireshark capture
# (Use GUI or: sudo tcpdump -i lo0 -w capture.pcap port 8888)

# Terminal 2: Start server
cd /Users/shehroz/Desktop/InfoSec/a2
source .venv/bin/activate
python -m app.server

# Terminal 3: Start client and interact
cd /Users/shehroz/Desktop/InfoSec/a2
source .venv/bin/activate
python -m app.client
# Register/login and send some messages

# Stop capture and analyze in Wireshark
```

## Troubleshooting

### "No interfaces available" (macOS)
```bash
# Install helper tool
brew install --cask wireshark-chmodbpf

# Or run with sudo (not recommended for GUI)
sudo wireshark
```

### "Permission denied" (Linux)
```bash
# Add user to wireshark group
sudo usermod -a -G wireshark $USER
# Log out and back in
```

### Can't see localhost traffic
- Use `lo0` interface (loopback)
- Or use `any` interface
- Make sure filter is: `tcp.port == 8888`

### Too much traffic
- Use display filter: `tcp.port == 8888`
- This shows only your application traffic

## Quick Reference

**Display Filters:**
- `tcp.port == 8888` - Your application traffic
- `tcp.port == 8888 && tcp.data` - Only data packets
- `tcp.port == 8888 && frame.len > 100` - Larger packets (likely encrypted data)

**Capture Filters:**
- `port 8888` - Capture only port 8888
- `host localhost && port 8888` - Localhost on port 8888

**Keyboard Shortcuts:**
- `Ctrl+E` - Start capture
- `Ctrl+E` - Stop capture
- `Ctrl+F` - Find packets
- `Ctrl+Shift+D` - Clear display filter

